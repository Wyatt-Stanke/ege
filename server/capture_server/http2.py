"""HTTP/2 sans-IO handler using h2."""
import logging

import h2.config
import h2.connection
import h2.events
import h2.exceptions

from . import routes
from .session import SessionStore

logger = logging.getLogger(__name__)


class Http2Connection:
    def __init__(
        self,
        session_store: SessionStore,
        conn_id: str,
        peer_addr: str,
    ) -> None:
        config = h2.config.H2Configuration(
            client_side=False, header_encoding="utf-8"
        )
        self.conn = h2.connection.H2Connection(config=config)
        self.conn.initiate_connection()

        self.session_store = session_store
        self.conn_id = conn_id
        self.peer_addr = peer_addr

        self.session_id: str | None = None
        self.request_count: int = 0
        self.first_request_path: str | None = None

        # stream_id -> {"headers": dict, "body": bytearray}
        self._streams: dict[int, dict] = {}

    def initial_bytes(self) -> bytes:
        """Server preface to send immediately after the handshake."""
        return self.conn.data_to_send(65535)

    def feed(self, data: bytes) -> bytes:
        """Feed decrypted bytes; return plaintext to encrypt and send."""
        try:
            events = self.conn.receive_data(data)
        except h2.exceptions.ProtocolError as exc:
            logger.warning("conn %s: h2 protocol error: %s", self.conn_id, exc)
            return self.conn.data_to_send(65535)

        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                hdrs = {h.lower(): v for h, v in event.headers}
                self._streams[event.stream_id] = {
                    "headers": hdrs,
                    "body": bytearray(),
                }
                if event.stream_ended:
                    self._dispatch_stream(event.stream_id)

            elif isinstance(event, h2.events.DataReceived):
                self.conn.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
                stream = self._streams.get(event.stream_id)
                if stream is not None:
                    stream["body"].extend(event.data)

            elif isinstance(event, h2.events.StreamEnded):
                if event.stream_id in self._streams:
                    self._dispatch_stream(event.stream_id)

            elif isinstance(event, h2.events.WindowUpdated):
                pass

            elif isinstance(event, (h2.events.RemoteSettingsChanged,
                                    h2.events.SettingsAcknowledged)):
                pass

            elif isinstance(event, h2.events.ConnectionTerminated):
                break

        return self.conn.data_to_send(65535)

    def _dispatch_stream(self, stream_id: int) -> None:
        stream = self._streams.pop(stream_id, None)
        if stream is None:
            return

        hdrs = stream["headers"]
        body = bytes(stream["body"])

        method = hdrs.get(":method", "GET")
        raw_path = hdrs.get(":path", "/")
        authority = hdrs.get(":authority", "") or hdrs.get("host", "")
        host_label = authority.split(".")[0].split(":")[0].lower()

        if "?" in raw_path:
            path, qs = raw_path.split("?", 1)
        else:
            path, qs = raw_path, ""

        if self.session_id is None:
            self.session_id, is_new = routes.resolve_session(
                method, path, qs, hdrs, host_label, self.conn_id, self.session_store
            )
        else:
            is_new = False

        request = routes.Request(
            method=method,
            path=path,
            query_string=qs,
            headers=hdrs,
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

        # Build h2 response headers (pseudo-headers first)
        response_headers = [
            (":status", str(resp.status)),
            ("content-length", str(len(resp.body))),
        ] + [(h, v) for h, v in resp.headers]

        try:
            end_stream = not resp.body
            self.conn.send_headers(stream_id, response_headers, end_stream=end_stream)
            if resp.body:
                self.conn.send_data(stream_id, resp.body, end_stream=True)
        except h2.exceptions.ProtocolError as exc:
            logger.warning(
                "conn %s stream %d: h2 send error: %s", self.conn_id, stream_id, exc
            )
