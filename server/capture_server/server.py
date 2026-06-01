"""asyncio TCP server entry point."""
import asyncio
import itertools
import logging
from functools import partial
from pathlib import Path

from . import tls as tls_mod
from .connection import handle_connection
from .session import SessionStore

logger = logging.getLogger(__name__)


async def run(
    bind: str,
    port: int,
    out_dir: Path,
    cert_dir: Path,
    idle_timeout: int,
    max_conn_bytes: int,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    cert_path, key_path = tls_mod.ensure_cert(cert_dir)
    ctx = tls_mod.build_context(cert_path, key_path)

    session_store = SessionStore(out_dir=out_dir, idle_timeout=idle_timeout)
    conn_counter = itertools.count(1)

    async def client_connected(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        conn_id = f"{next(conn_counter):04d}"
        await handle_connection(
            reader=reader,
            writer=writer,
            ctx=ctx,
            session_store=session_store,
            out_dir=out_dir,
            max_conn_bytes=max_conn_bytes,
            conn_id=conn_id,
        )

    server = await asyncio.start_server(
        client_connected,
        host=bind,
        port=port,
        # ssl=None — TLS is handled manually via MemoryBIO
    )

    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info("Listening on %s (TLS, no ssl= wrapper)", addrs)

    async with server:
        try:
            await server.serve_forever()
        except KeyboardInterrupt:
            pass
