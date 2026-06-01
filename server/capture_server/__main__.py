"""Entry point: `python -m capture_server`."""
import argparse
import asyncio
import logging
import os
from pathlib import Path

from .server import run


def main() -> None:
    def env(key: str, default: str) -> str:
        return os.environ.get(f"CAPTURE_{key}", default)

    parser = argparse.ArgumentParser(prog="capture_server")
    parser.add_argument("--bind", default=env("BIND", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(env("PORT", "443")))
    parser.add_argument("--out", default=env("OUT", "./captures"))
    parser.add_argument("--cert-dir", default=env("CERT_DIR", "./certs"))
    parser.add_argument(
        "--idle-timeout", type=int, default=int(env("IDLE_TIMEOUT", "60"))
    )
    parser.add_argument(
        "--max-conn-bytes",
        type=int,
        default=int(env("MAX_CONN_BYTES", str(5 * 1024 * 1024))),
    )
    parser.add_argument("--log-level", default=env("LOG_LEVEL", "INFO"))

    args = parser.parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    asyncio.run(
        run(
            bind=args.bind,
            port=args.port,
            out_dir=Path(args.out),
            cert_dir=Path(args.cert_dir),
            idle_timeout=args.idle_timeout,
            ci_mode=args.ci_mode,
            max_conn_bytes=args.max_conn_bytes,
        )
    )


if __name__ == "__main__":
    main()
