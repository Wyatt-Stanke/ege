"""HTTP/1.1 sans-IO handler using h11."""
import logging

import h11

from . import routes
from .session import SessionStore

logger = logging.getLogger(__name__)


class Http1Connection:
    def __init__(
        self,
        session_store: SessionStore,
        conn_id: str,
        peer_addr: str,
    ) -> None:
        self.conn = h11.Connection(our_role=h11.SERVER)
        self.session_store = session_store
        self.conn_id = conn_id
        self.peer_addr = peer_addr

        self.session_id: str | None = None
        self.request_count: int = 0
        self.first_request_path: str | None = None

        self._pending_req: h11.Request | None = None
        self._pending_body = bytearray()

    # ------------------------------------------------------------------

    def feed(self, data: bytes) -> bytes:
        """Feed decrypted bytes; return plaintext bytes to encrypt and send."""
        self.conn.receive_data(data)
        output = bytearray()

        while True:
            try:
                event = self.conn.next_event()
            except h11.RemoteProtocolError as exc:
                logger.warning("conn %s: h11 protocol error: %s", self.conn_id, exc)
                break

            if isinstance(event, (h11.NEED_DATA, h11.PAUSED)):
                break

            if isinstance(event, h11.Request):
                self._pending_req = event
                self._pending_body = bytearray()

            elif isinstance(event, h11.Data):
                if self._pending_req is not None:
                    self._pending_body.extend(event.data)

            elif isinstance(event, h11.EndOfMessage):
                if self._pending_req is not None:
                    output.extend(self._dispatch())
                    self._pending_req = None
                    self._pending_body = bytearray()
                    try:
                        self.conn.start_next_cycle()
                    except h11.LocalProtocolError:
                        break

            elif isinstance(event, h11.ConnectionClosed):
                break

        return bytes(output)

    # ------------------------------------------------------------------

    def _dispatch(self) -> bytes:
        req = self._pending_req
        body = bytes(self._pending_body)

        headers = {
            name.lower().decode(): value.decode()
            for name, value in req.headers
        }
        host = headers.get("host", "")
        host_label = host.split(".")[0].split(":")[0].lower()

        raw_target = req.target.decode()
        if "?" in raw_target:
            path, qs = raw_target.split("?", 1)
        else:
            path, qs = raw_target, ""

        method = req.method.decode()

        # Resolve session on the first request in this connection
        if self.session_id is None:
            self.session_id, is_new = routes.resolve_session(
                method, path, qs, headers, host_label, self.conn_id, self.session_store
            )
        else:
            is_new = False

        request = routes.Request(
            method=method,
            path=path,
            query_string=qs,
            headers=headers,
            body=body,
            host_label=host_label,
            session_id=self.session_id,
            conn_id=self.conn_id,
            is_new_session=is_new,
        )

        resp = routes.dispatch(request, self.session_store)

        self.request_count += 1
        if self.first_request_path is None:
            self.first_request_path = path
        if resp.new_session_id:
            self.session_id = resp.new_session_id

        # Encode through h11
        if resp.status == 101:
            # 101 Switching Protocols MUST use InformationalResponse
            # and transitions the state to SWITCHED_PROTOCOL.
            out = self.conn.send(
                h11.InformationalResponse(status_code=101, headers=resp.headers)
            )
            # Do NOT send Data or EndOfMessage for a 101 status.
        else:
            h11_headers = list(resp.headers)
            h11_headers.append(("content-length", str(len(resp.body))))
            
            out = self.conn.send(
                h11.Response(status_code=resp.status, headers=h11_headers)
            )
            if resp.body:
                out += self.conn.send(h11.Data(data=resp.body))
            out += self.conn.send(h11.EndOfMessage())

        return out
