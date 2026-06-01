"""Final JSON output schema builder (schema_version=1)."""
import hashlib

from .tls.records import ClientHello
from .tls.clienthello import build_tls_info
from .tls.registry import name_h2_setting
from .h2.frames import H2Info
from .h2.akamai import build_akamai_string, akamai_hash
from .fingerprint.ja3 import compute_ja3
from .fingerprint.ja4 import compute_ja4
from .fingerprint.peetprint import compute_peetprint
from .config import build_config


def build_output(
    session_id: str,
    captured_at: str,
    report: dict | None,
    canonical_conn_id: str,
    canonical_ch: ClientHello,
    canonical_meta: dict,
    canonical_h2: H2Info | None,
    permute_extensions: bool,
    extension_order: list[int] | None,
) -> dict:
    """Assemble the full canonical fingerprint JSON."""

    # ---- Source block ----
    source = {
        "user_agent": report.get("user_agent") if report else None,
        "ua_client_hints": report.get("ua_client_hints") if report else None,
        "navigator": report.get("navigator") if report else None,
        "report_present": report is not None,
    }

    # ---- TLS block ----
    tls_info = build_tls_info(canonical_ch)
    tls_info["canonical_conn"] = canonical_conn_id
    tls_info["negotiated_version"] = canonical_meta.get("tls_version")
    tls_info["alpn_selected"] = canonical_meta.get("alpn")
    tls_info["sni"] = canonical_meta.get("sni")
    # Override extension order/permutation from variation analysis
    tls_info["extensions"]["order"] = "permuted" if permute_extensions else "fixed"

    # ---- H2 block ----
    if canonical_h2:
        h2_block = {
            "settings": [
                [name_h2_setting(k), v] for k, v in canonical_h2.settings
            ],
            "initial_window_update_increment": canonical_h2.window_update,
            "priority_frames": [
                list(f) for f in canonical_h2.priority_frames
            ],
            "uses_extensible_priorities": canonical_h2.uses_extensible_priorities,
            "pseudo_header_order": canonical_h2.pseudo_header_order,
            "request_header_order_sample": canonical_h2.request_headers,
        }
    else:
        h2_block = None

    # ---- Config block ----
    config = build_config(canonical_ch, canonical_h2, permute_extensions, extension_order)

    # ---- Fingerprints ----
    ja3_str, ja3_hash = compute_ja3(canonical_ch)
    ja4, ja4_r = compute_ja4(canonical_ch)
    peet = compute_peetprint(canonical_ch)

    akamai_str = build_akamai_string(canonical_h2) if canonical_h2 else None
    akamai_md5 = akamai_hash(akamai_str) if akamai_str else None

    fingerprints = {
        "ja3": ja3_str,
        "ja3_hash": ja3_hash,
        "ja4": ja4,
        "ja4_r": ja4_r,
        "peetprint": peet,
        "akamai_h2": akamai_str,
        "akamai_h2_hash": akamai_md5,
    }

    # ---- Raw bytes references ----
    ch_hex = canonical_ch.raw_bytes.hex()
    ch_sha256 = hashlib.sha256(canonical_ch.raw_bytes).hexdigest()
    raw = {
        "client_hello_hex": ch_hex,
        "client_hello_sha256": ch_sha256,
        "first_settings_frame_hex": canonical_h2.first_settings_frame_hex if canonical_h2 else None,
        "first_headers_frame_hex": canonical_h2.first_headers_frame_hex if canonical_h2 else None,
    }

    return {
        "schema_version": 1,
        "session_id": session_id,
        "captured_at": captured_at,
        "source": source,
        "tls": tls_info,
        "http2": h2_block,
        "config": config,
        "fingerprints": fingerprints,
        "raw": raw,
    }


def build_variation_output(
    session_id: str,
    canonical_conn_id: str,
    conn_count: int,
    variation_report: dict,
) -> dict:
    return {
        "schema_version": 1,
        "session_id": session_id,
        "canonical_conn": canonical_conn_id,
        "conn_count": conn_count,
        "stable": variation_report.get("stable", []),
        "varied": variation_report.get("varied", {}),
        "anomalies": variation_report.get("anomalies", []),
    }
