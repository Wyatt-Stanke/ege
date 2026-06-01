"""Transport-agnostic route handlers.

Request and Response are plain dataclasses.  http1.py / http2.py are the only
things that know about h11 / h2; they call dispatch() here.
"""
import hashlib
import base64
import json
import logging
import struct
import urllib.parse
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .session import SessionStore

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Tiny static assets generated in-process
# ------------------------------------------------------------------

def _make_pixel_png() -> bytes:
    """Generate a minimal 1×1 transparent PNG."""
    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)  # RGBA
    raw_scanline = bytes([0, 0, 0, 0, 0])  # filter + RGBA transparent
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr_data)
        + chunk(b"IDAT", zlib.compress(raw_scanline))
        + chunk(b"IEND", b"")
    )


_PIXEL_PNG = _make_pixel_png()
_STATIC_DIR = Path(__file__).parent / "static"


def _read_static(filename: str) -> bytes:
    return (_STATIC_DIR / filename).read_bytes()


# ------------------------------------------------------------------
# Request / Response types
# ------------------------------------------------------------------

@dataclass
class Request:
    method: str
    path: str
    query_string: str
    headers: dict          # lowercase keys, string values
    body: bytes
    host_label: str        # leftmost label of Host / :authority
    session_id: Optional[str]
    conn_id: str
    is_new_session: bool = False


@dataclass
class Response:
    status: int
    headers: list = field(default_factory=list)  # list of (name, value) str tuples
    body: bytes = b""
    new_session_id: Optional[str] = None


# ------------------------------------------------------------------
# Session helpers
# ------------------------------------------------------------------

def _extract_qs_param(qs: str, name: str) -> Optional[str]:
    for k, v in urllib.parse.parse_qsl(qs):
        if k == name:
            return v
    return None


def _extract_cookie(cookie_header: str, name: str) -> Optional[str]:
    for part in cookie_header.split(";"):
        k, _, v = part.strip().partition("=")
        if k.strip() == name:
            return urllib.parse.unquote(v.strip())
    return None


def resolve_session(
    method: str,
    path: str,
    qs: str,
    headers: dict,
    host_label: str,
    conn_id: str,
    session_store: SessionStore,
) -> tuple[str, bool]:
    """Return (session_id, is_new)."""
    # 1. ?sid= query param
    sid = _extract_qs_param(qs, "sid")
    if sid:
        session_store.get_or_create(sid)
        return sid, False

    # 2. Cookie
    cookie_hdr = headers.get("cookie", "")
    sid = _extract_cookie(cookie_hdr, "__capture_sid")
    if sid:
        session_store.get_or_create(sid)
        return sid, False

    # 3. Mint for the "owner" origin on entry-point paths
    if host_label in ("capture", "localhost") and method == "GET" and path in (
        "/",
        "/payload.js",
        "/session",
    ):
        state = session_store.new_session()
        return state.id, True

    # 4. Orphan
    return f"orphan-{conn_id}", False


# ------------------------------------------------------------------
# CORS helpers
# ------------------------------------------------------------------

_CORS_HEADERS_COMMON = [
    ("access-control-allow-methods", "GET, POST, OPTIONS"),
    ("access-control-allow-headers", "Content-Type, X-Capture-Probe"),
    ("access-control-expose-headers", "X-Capture-Sid"),
    ("access-control-max-age", "0"),
]


def _cors_headers(origin: str) -> list:
    if origin:
        return [
            ("access-control-allow-origin", origin),
            ("access-control-allow-credentials", "true"),
        ] + _CORS_HEADERS_COMMON
    return [("access-control-allow-origin", "*")] + _CORS_HEADERS_COMMON


def _is_cors_host(host_label: str) -> bool:
    return host_label in ("api", "cdn", "ws")


# ------------------------------------------------------------------
# Route dispatch
# ------------------------------------------------------------------

def dispatch(req: Request, session_store: SessionStore) -> Response:
    origin = req.headers.get("origin", "")

    # -- OPTIONS preflight -------------------------------------------------
    if req.method == "OPTIONS":
        resp = Response(
            status=204,
            headers=_cors_headers(origin),
        )
        _maybe_set_cookie(req, resp)
        return resp

    hl = req.host_label

    # -- WebSocket upgrade (ws.*) -----------------------------------------
    if hl == "ws" and req.path == "/ws":
        return _handle_ws_upgrade(req)

    # -- api.* endpoints --------------------------------------------------
    if hl == "api":
        return _handle_api(req, origin)

    # -- cdn.* subresources -----------------------------------------------
    if hl == "cdn":
        return _handle_cdn(req, origin)

    # -- capture.* / localhost main origin --------------------------------
    resp = _handle_main(req, session_store)
    _maybe_set_cookie(req, resp)
    return resp


def _maybe_set_cookie(req: Request, resp: Response) -> None:
    if req.is_new_session and req.session_id:
        resp.headers.append((
            "set-cookie",
            f"__capture_sid={req.session_id}; Path=/; SameSite=None; Secure; Max-Age=3600",
        ))
        resp.new_session_id = req.session_id


# ------------------------------------------------------------------
# Main origin handlers
# ------------------------------------------------------------------

def _handle_main(req: Request, session_store: SessionStore) -> Response:
    path = req.path
    method = req.method

    if method == "GET" and path == "/":
        body = _read_static("index.html")
        return Response(
            status=200,
            headers=[("content-type", "text/html; charset=utf-8")],
            body=body,
        )
    
    if method == "GET" and path == "/session":
        if req.session_id:
            return Response(
                status=200,
                headers=[("content-type", "application/json")],
                body=json.dumps({
                    "session_id": req.session_id,
                }).encode(),
            )
        return Response(status=404, headers=[("content-type", "text/plain")], body=b"Session not found")

    if method == "GET" and path == "/payload.js":
        body = _read_static("payload.js")
        return Response(
            status=200,
            headers=[("content-type", "application/javascript; charset=utf-8")],
            body=body,
        )

    if method == "POST" and path == "/report":
        if req.session_id:
            try:
                report = json.loads(req.body)
            except json.JSONDecodeError:
                report = {"raw": req.body.decode(errors="replace")}
            session_store.set_report(req.session_id, report)
        return Response(status=204)

    if method == "POST" and path == "/done":
        if req.session_id and not req.session_id.startswith("orphan-"):
            session_store.finalize(req.session_id, "explicit")
        return Response(status=204)

    if path == "/probe/xhr" and method == "GET":
        return Response(
            status=200,
            headers=[("content-type", "text/plain")],
            body=b"ok",
        )

    if path == "/probe/post-form" and method == "POST":
        return Response(status=200, headers=[("content-type", "text/plain")], body=b"ok")

    if path == "/probe/post-multipart" and method == "POST":
        return Response(status=200, headers=[("content-type", "text/plain")], body=b"ok")

    if path == "/probe/post-json" and method == "POST":
        return Response(status=200, headers=[("content-type", "text/plain")], body=b"ok")

    if path == "/probe/beacon" and method == "POST":
        return Response(status=204)

    if method == "GET" and path == "/asset/image.png":
        return Response(
            status=200,
            headers=[("content-type", "image/png")],
            body=_PIXEL_PNG,
        )

    if method == "GET" and path == "/asset/script.js":
        return Response(
            status=200,
            headers=[("content-type", "application/javascript")],
            body=b"",
        )

    if method == "GET" and path == "/asset/style.css":
        return Response(
            status=200,
            headers=[("content-type", "text/css")],
            body=b"",
        )
    
    if method == "GET" and path == "/die":
        raise KeyboardInterrupt("Server done (triggered /die)")

    return Response(status=404, headers=[("content-type", "text/plain")], body=b"Not Found")


# ------------------------------------------------------------------
# api.* handlers
# ------------------------------------------------------------------

def _handle_api(req: Request, origin: str) -> Response:
    cors = _cors_headers(origin)
    path = req.path
    method = req.method

    if path == "/probe/cors-simple" and method in ("GET", "POST"):
        return Response(status=200, headers=cors + [("content-type", "text/plain")], body=b"ok")

    if path == "/probe/cors-preflight" and method in ("POST", "OPTIONS"):
        return Response(status=200, headers=cors + [("content-type", "text/plain")], body=b"ok")

    if path == "/probe/cors-creds" and method == "GET":
        return Response(status=200, headers=cors + [("content-type", "text/plain")], body=b"ok")

    return Response(status=404, headers=cors + [("content-type", "text/plain")], body=b"Not Found")


# ------------------------------------------------------------------
# cdn.* handlers
# ------------------------------------------------------------------

def _handle_cdn(req: Request, origin: str) -> Response:
    cors = _cors_headers(origin)
    path = req.path

    if path.startswith("/asset/"):
        name = path[len("/asset/"):]
        if name == "image.png":
            return Response(
                status=200,
                headers=cors + [("content-type", "image/png")],
                body=_PIXEL_PNG,
            )
        if name == "script.js":
            return Response(
                status=200,
                headers=cors + [("content-type", "application/javascript")],
                body=b"",
            )
        if name == "style.css":
            return Response(
                status=200,
                headers=cors + [("content-type", "text/css")],
                body=b"",
            )

    return Response(status=404, headers=cors + [("content-type", "text/plain")], body=b"Not Found")


# ------------------------------------------------------------------
# WebSocket upgrade
# ------------------------------------------------------------------

def _handle_ws_upgrade(req: Request) -> Response:
    ws_key = req.headers.get("sec-websocket-key", "")
    guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    accept = base64.b64encode(
        hashlib.sha1((ws_key + guid).encode()).digest()
    ).decode()
    return Response(
        status=101,
        headers=[
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-accept", accept),
        ],
        body=b"",
    )
