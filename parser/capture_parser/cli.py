"""CLI: `python -m capture_parser SESSION_DIR [SESSION_DIR …]`"""
import argparse
import json
import logging
import sys
from pathlib import Path

from .session import parse_session

logger = logging.getLogger(__name__)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="capture_parser",
        description="Parse TLS capture sessions and produce fingerprint JSON.",
    )
    parser.add_argument(
        "session_dirs",
        nargs="+",
        metavar="SESSION_DIR",
        help="One or more captures/{session_id}/ directories to parse.",
    )
    parser.add_argument(
        "--out",
        default="./fingerprints",
        metavar="DIR",
        help="Output directory (default: ./fingerprints)",
    )
    parser.add_argument(
        "--db",
        default=None,
        metavar="PATH",
        help="Append canonical records to this JSONL file.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero on any per-connection parse error.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Single-line JSON output (default: pretty-printed).",
    )
    parser.add_argument(
        "--no-variation",
        action="store_true",
        help="Skip writing the .variation.json file.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        metavar="LEVEL",
        help="Logging level (default: INFO).",
    )

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_kwargs: dict = {"sort_keys": True}
    if args.compact:
        json_kwargs["separators"] = (",", ":")
    else:
        json_kwargs["indent"] = 2

    db_path = Path(args.db) if args.db else None

    all_ok = True

    for raw_path in args.session_dirs:
        session_dir = Path(raw_path)
        session_id = session_dir.name

        try:
            record, variation = parse_session(session_dir, strict=args.strict)
        except Exception as exc:
            logger.error("Session %s: fatal error: %s", session_id, exc)
            all_ok = False
            continue

        if record is None:
            logger.error("Session %s: no output produced", session_id)
            all_ok = False
            continue

        # Write canonical fingerprint
        fp_path = out_dir / f"{session_id}.json"
        fp_path.write_text(json.dumps(record, **json_kwargs))
        logger.info("Wrote %s", fp_path)

        # Write variation report
        if not args.no_variation and variation is not None:
            var_path = out_dir / f"{session_id}.variation.json"
            var_path.write_text(json.dumps(variation, **json_kwargs))
            logger.info("Wrote %s", var_path)

        # Append to JSONL DB
        if db_path:
            db_line = json.dumps({
                "schema_version": record.get("schema_version"),
                "session_id": session_id,
                "user_agent": record.get("source", {}).get("user_agent"),
                "ja3_hash": record.get("fingerprints", {}).get("ja3_hash"),
                "ja4": record.get("fingerprints", {}).get("ja4"),
                "akamai_h2_hash": record.get("fingerprints", {}).get("akamai_h2_hash"),
                "config": record.get("config"),
                "captured_at": record.get("captured_at"),
            }, sort_keys=True)
            with open(db_path, "a") as f:
                f.write(db_line + "\n")
            logger.info("Appended to %s", db_path)

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
