"""Session directory walker.

Parses all conn_NNNN/ subdirectories in a captured session directory,
picks a canonical connection, runs variation analysis, and assembles
the full fingerprint record.
"""
import json
import logging
from pathlib import Path

from .tls.records import parse_client_hello
from .h2.frames import parse_h2
from .variation import analyze_variation
from .output import build_output, build_variation_output

logger = logging.getLogger(__name__)


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return None


def parse_session(
    session_dir: Path,
    strict: bool = False,
) -> tuple[dict | None, dict | None]:
    """
    Parse a session directory.

    Returns (canonical_record, variation_record).
    Both are plain dicts suitable for json.dumps.
    Returns (None, None) on fatal error.
    """

    session_id = session_dir.name

    # Load session.json and report.json (both optional)
    session_meta = _load_json(session_dir / "session.json") or {}
    report = _load_json(session_dir / "report.json")

    captured_at = session_meta.get("started_at", "")

    # Discover conn_NNNN directories sorted by name
    conn_dirs = sorted(
        d for d in session_dir.iterdir() if d.is_dir() and d.name.startswith("conn_")
    )

    if not conn_dirs:
        logger.error("No conn_* directories found in %s", session_dir)
        return None, None

    # Parse each connection
    parsed_conns: list[tuple[str, object, dict, object]] = []
    # [(conn_id, ClientHello, meta, H2Info|None)]

    for conn_dir in conn_dirs:
        conn_id = conn_dir.name[len("conn_"):]
        raw_path = conn_dir / "raw_inbound.bin"
        dec_path = conn_dir / "decrypted_inbound.bin"
        meta_path = conn_dir / "meta.json"

        if not raw_path.exists():
            logger.warning("conn %s: raw_inbound.bin missing, skipping", conn_id)
            if strict:
                raise FileNotFoundError(f"Missing {raw_path}")
            continue

        meta = _load_json(meta_path) or {}

        try:
            ch = parse_client_hello(raw_path.read_bytes())
        except Exception as exc:
            logger.warning("conn %s: ClientHello parse error: %s", conn_id, exc)
            if strict:
                raise
            continue

        # Parse H2 if applicable
        h2_info = None
        if meta.get("alpn") == "h2" and dec_path.exists():
            try:
                h2_info = parse_h2(dec_path.read_bytes())
            except Exception as exc:
                logger.warning("conn %s: H2 parse error: %s", conn_id, exc)
                if strict:
                    raise

        parsed_conns.append((conn_id, ch, meta, h2_info))

    if not parsed_conns:
        logger.error("No connections parsed successfully in %s", session_dir)
        return None, None

    # Pick canonical connection: first by started_at where SNI is capture.localhost
    # Fall back to first overall.
    canonical = None
    for conn_id, ch, meta, h2 in parsed_conns:
        sni = meta.get("sni", "")
        if sni and "capture" in sni:
            canonical = (conn_id, ch, meta, h2)
            break
    if canonical is None:
        canonical = parsed_conns[0]

    canonical_conn_id, canonical_ch, canonical_meta, canonical_h2 = canonical

    # Run variation analysis across all parsed CHs
    ch_pairs = [(cid, ch) for cid, ch, meta, h2 in parsed_conns]
    variation_report, permute_extensions, extension_order = analyze_variation(ch_pairs)

    # Build output
    record = build_output(
        session_id=session_id,
        captured_at=captured_at,
        report=report,
        canonical_conn_id=canonical_conn_id,
        canonical_ch=canonical_ch,
        canonical_meta=canonical_meta,
        canonical_h2=canonical_h2,
        permute_extensions=permute_extensions,
        extension_order=extension_order,
    )

    variation = build_variation_output(
        session_id=session_id,
        canonical_conn_id=canonical_conn_id,
        conn_count=len(parsed_conns),
        variation_report=variation_report,
    )

    return record, variation
