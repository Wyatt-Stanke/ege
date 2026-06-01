"""JA4 and JA4_r fingerprint computation.

Spec: https://github.com/FoxIO-LLC/ja4
"""
import hashlib

from ..tls.records import ClientHello
from ..tls.grease import filter_grease, is_grease_u16


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ext(ch: ClientHello, ext_type: int):
    for e in ch.extensions:
        if e.ext_type == ext_type:
            return e
    return None


_TLS_VERSION_MAP = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
}


def _tls_version_code(ch: ClientHello) -> str:
    """Use highest offered version from supported_versions ext; fall back to legacy."""
    sv_ext = _ext(ch, 0x002B)
    if sv_ext:
        versions = [v for v in sv_ext.parsed.get("versions", []) if not is_grease_u16(v)]
        if versions:
            return _TLS_VERSION_MAP.get(max(versions), "00")
    return _TLS_VERSION_MAP.get(ch.legacy_version, "00")


def _alpn_code(ch: ClientHello) -> str:
    alpn_ext = _ext(ch, 0x0010)
    if not alpn_ext:
        return "00"
    protocols = alpn_ext.parsed.get("protocols", [])
    if not protocols:
        return "00"
    first = protocols[0]
    if len(first) >= 2:
        return first[0] + first[-1]
    if len(first) == 1:
        return first[0] + first[0]
    return "00"


# ---------------------------------------------------------------------------
# JA4 / JA4_r
# ---------------------------------------------------------------------------

def compute_ja4(ch: ClientHello) -> tuple[str, str]:
    """Return (ja4, ja4_r)."""

    protocol = "t"
    tls_ver = _tls_version_code(ch)
    sni = "d" if _ext(ch, 0x0000) else "i"

    ciphers_no_grease = filter_grease(ch.cipher_suites)
    cipher_count = min(len(ciphers_no_grease), 99)

    ext_types = [e.ext_type for e in ch.extensions]
    exts_no_grease = filter_grease(ext_types)
    ext_count = min(len(exts_no_grease), 99)

    alpn = _alpn_code(ch)

    prefix = f"{protocol}{tls_ver}{sni}{cipher_count:02d}{ext_count:02d}{alpn}"

    # ---- Cipher hash ----
    # SHA256 of sorted comma-joined 4-char hex ciphers
    sorted_ciphers = sorted(f"{c:04x}" for c in ciphers_no_grease)
    cipher_input = ",".join(sorted_ciphers)
    cipher_hash = hashlib.sha256(cipher_input.encode()).hexdigest()[:12]

    # ---- Extension hash ----
    # Extensions: non-GREASE, excluding SNI (0x0000) and ALPN (0x0010), sorted
    ext_for_hash = [v for v in exts_no_grease if v not in (0x0000, 0x0010)]
    sorted_exts = sorted(f"{v:04x}" for v in ext_for_hash)
    exts_part = ",".join(sorted_exts)

    # Sig algs: in original order
    sa_ext = _ext(ch, 0x000D)
    if sa_ext:
        sigalgs = sa_ext.parsed.get("algorithms", [])
        sigalgs_part = ",".join(f"{v:04x}" for v in sigalgs)
    else:
        sigalgs_part = ""

    ext_hash_input = exts_part + "_" + sigalgs_part
    ext_hash = hashlib.sha256(ext_hash_input.encode()).hexdigest()[:12]

    ja4 = f"{prefix}_{cipher_hash}_{ext_hash}"
    ja4_r = f"{prefix}_{cipher_input}_{ext_hash_input}"

    return ja4, ja4_r
