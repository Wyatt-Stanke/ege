"""Per-connection coroutine: BIO pump + capture to disk."""
import asyncio
import json
import logging
import ssl
from datetime import datetime, timezone
from pathlib import Path

from . import tls
from .http1 import Http1Connection
from .http2 import Http2Connection
from .session import SessionStore

logger = logging.getLogger(__name__)

READ_SIZE = 16384
IDLE_TIMEOUT = 30.0  # seconds of socket inactivity before closing


async def handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ctx: ssl.SSLContext,
    session_store: SessionStore,
    out_dir: Path,
    max_conn_bytes: int,
    conn_id: str,
) -> None:
    peer = writer.get_extra_info("peername") or ("unknown", 0)
    peer_str = f"{peer[0]}:{peer[1]}"
    logger.debug("conn %s: accepted from %s", conn_id, peer_str)

    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    sslobj = ctx.wrap_bio(incoming, outgoing, server_side=True)

    raw_inbound = bytearray()
    decrypted_inbound = bytearray()
    raw_capped = False
    dec_capped = False

    handshaked = False
    http_conn: Http1Connection | Http2Connection | None = None

    alpn = "http/1.1"
    tls_version: str | None = None
    cipher: str | None = None
    sni: str | None = None

    started_at = datetime.now(timezone.utc)

    try:
        while True:
            # Read from socket with idle timeout
            try:
                chunk = await asyncio.wait_for(reader.read(READ_SIZE), IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                logger.debug("conn %s: idle timeout", conn_id)
                break
            except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
                break

            if not chunk:
                try:
                    incoming.write_eof()
                except Exception:
                    pass
                break

            # Capture raw bytes (pre-TLS)
            if not raw_capped:
                if len(raw_inbound) + len(chunk) > max_conn_bytes:
                    raw_capped = True
                    logger.warning("conn %s: raw_inbound cap reached", conn_id)
                else:
                    raw_inbound.extend(chunk)

            # Feed into the TLS BIO
            try:
                incoming.write(chunk)
            except ssl.SSLError:
                break

            # TLS handshake
            if not handshaked:
                try:
                    sslobj.do_handshake()
                    handshaked = True
                    sni = tls.pop_sni(sslobj)
                    alpn = sslobj.selected_alpn_protocol() or "http/1.1"
                    tls_version = sslobj.version()
                    cipher_info = sslobj.cipher()
                    cipher = cipher_info[0] if cipher_info else None

                    if alpn == "h2":
                        http_conn = Http2Connection(session_store, conn_id, peer_str)
                        init_data = http_conn.initial_bytes()
                        if init_data:
                            sslobj.write(init_data)
                    else:
                        http_conn = Http1Connection(session_store, conn_id, peer_str)

                    logger.info(
                        "conn %s: handshake done sni=%s alpn=%s tls=%s",
                        conn_id, sni, alpn, tls_version,
                    )
                except ssl.SSLWantReadError:
                    pass
                except ssl.SSLError as exc:
                    logger.warning("conn %s: TLS handshake error: %s", conn_id, exc)
                    break

            # Drain outgoing after handshake attempt
            out = outgoing.read()
            if out:
                try:
                    writer.write(out)
                    await writer.drain()
                except (ConnectionResetError, BrokenPipeError):
                    break

            # Decrypt and process application data
            if handshaked and http_conn is not None:
                while True:
                    try:
                        plain = sslobj.read(READ_SIZE)
                        if not plain:
                            break
                        if not dec_capped:
                            if len(decrypted_inbound) + len(plain) > max_conn_bytes:
                                dec_capped = True
                                logger.warning(
                                    "conn %s: decrypted_inbound cap reached", conn_id
                                )
                            else:
                                decrypted_inbound.extend(plain)

                        resp_bytes = http_conn.feed(plain)
                        if resp_bytes:
                            sslobj.write(resp_bytes)
                    except ssl.SSLWantReadError:
                        break
                    except ssl.SSLError as exc:
                        logger.warning("conn %s: SSL read error: %s", conn_id, exc)
                        break

                # Drain any response bytes to the socket
                out = outgoing.read()
                if out:
                    try:
                        writer.write(out)
                        await writer.drain()
                    except (ConnectionResetError, BrokenPipeError):
                        break

    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        ended_at = datetime.now(timezone.utc)
        session_id = (http_conn.session_id if http_conn else None) or f"orphan-{conn_id}"
        request_count = http_conn.request_count if http_conn else 0
        first_path = http_conn.first_request_path if http_conn else None

        # Write capture files
        conn_dir = out_dir / session_id / f"conn_{conn_id}"
        conn_dir.mkdir(parents=True, exist_ok=True)
        (conn_dir / "raw_inbound.bin").write_bytes(bytes(raw_inbound))
        (conn_dir / "decrypted_inbound.bin").write_bytes(bytes(decrypted_inbound))

        meta = {
            "conn_id": conn_id,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "peer_addr": peer_str,
            "sni": sni,
            "alpn": alpn if handshaked else None,
            "tls_version": tls_version,
            "cipher": cipher,
            "session_id": session_id,
            "bytes_in": len(raw_inbound),
            "bytes_out": 0,
            "raw_inbound_bytes": len(raw_inbound),
            "decrypted_inbound_bytes": len(decrypted_inbound),
            "request_count": request_count,
            "first_request_path": first_path,
        }
        (conn_dir / "meta.json").write_text(json.dumps(meta, indent=2))

        # Register with session store (skip orphans)
        if not session_id.startswith("orphan-"):
            summary = {
                "conn_id": conn_id,
                "sni": sni,
                "alpn": alpn if handshaked else None,
                "requests": request_count,
            }
            session_store.add_conn(session_id, conn_id)
            session_store.add_conn_summary(session_id, summary)

        logger.info(
            "conn %s: closed — session=%s reqs=%d raw=%d dec=%d",
            conn_id, session_id, request_count,
            len(raw_inbound), len(decrypted_inbound),
        )
