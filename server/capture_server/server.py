"""asyncio TCP server entry point."""
import asyncio
import itertools
import logging
from contextlib import suppress
from functools import partial
from pathlib import Path

from . import tls as tls_mod
from .connection import handle_connection
from .session import SessionStore

logger = logging.getLogger(__name__)

CI_POLL_INTERVAL = 10.0
CI_IDLE_TIMEOUT = 10.0


async def run(
    bind: str,
    port: int,
    out_dir: Path,
    cert_dir: Path,
    idle_timeout: int,
    ci_mode: bool,
    max_conn_bytes: int,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    cert_path, key_path = tls_mod.ensure_cert(cert_dir)
    ctx = tls_mod.build_context(cert_path, key_path)

    session_store = SessionStore(out_dir=out_dir, idle_timeout=idle_timeout)
    conn_counter = itertools.count(1)

    loop = asyncio.get_running_loop()
    last_activity = loop.time()
    active_conns = 0
    first_request = asyncio.Event()

    async def client_connected(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        nonlocal last_activity, active_conns
        conn_id = f"{next(conn_counter):04d}"
        active_conns += 1
        last_activity = loop.time()
        first_request.set()
        try:
            await handle_connection(
                reader=reader,
                writer=writer,
                ctx=ctx,
                session_store=session_store,
                out_dir=out_dir,
                max_conn_bytes=max_conn_bytes,
                conn_id=conn_id,
            )
        finally:
            active_conns -= 1
            last_activity = loop.time()

    server = await asyncio.start_server(
        client_connected,
        host=bind,
        port=port,
        # ssl=None — TLS is handled manually via MemoryBIO
    )

    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info("Listening on %s (TLS, no ssl= wrapper)", addrs)

    async def ci_idle_watchdog() -> None:
        # Wait for the first request so we don't exit before the CI client
        # has had a chance to connect.
        await first_request.wait()
        while True:
            await asyncio.sleep(CI_POLL_INTERVAL)
            if active_conns:
                continue  # something is mid-flight; not idle
            idle = loop.time() - last_activity
            if idle >= CI_IDLE_TIMEOUT:
                logger.info(
                    "CI mode: no requests processed in %.1fs, shutting down", idle
                )
                return

    async with server:
        if ci_mode:
            serve_task = asyncio.create_task(server.serve_forever())
            await ci_idle_watchdog()
            serve_task.cancel()
            with suppress(asyncio.CancelledError):
                await serve_task
        else:
            await server.serve_forever()