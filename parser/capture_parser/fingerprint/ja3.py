"""JA3 fingerprint computation."""
import hashlib

from ..tls.records import ClientHello
from ..tls.grease import filter_grease


def _ext(ch: ClientHello, ext_type: int):
    for e in ch.extensions:
        if e.ext_type == ext_type:
            return e
    return None


def compute_ja3(ch: ClientHello) -> tuple[str, str]:
    """Return (ja3_string, ja3_hash)."""

    # TLSVersion: decimal of legacy_version
    version = str(ch.legacy_version)

    # Ciphers: decimal, GREASE excluded, dash-joined, in order
    ciphers = filter_grease(ch.cipher_suites)
    ciphers_str = "-".join(str(c) for c in ciphers)

    # Extensions: decimal types, GREASE excluded, dash-joined, in order
    ext_types = [e.ext_type for e in ch.extensions]
    exts = filter_grease(ext_types)
    exts_str = "-".join(str(e) for e in exts)

    # EllipticCurves: from supported_groups extension, GREASE excluded
    sg_ext = _ext(ch, 0x000A)
    if sg_ext:
        groups = filter_grease(sg_ext.parsed.get("groups", []))
        groups_str = "-".join(str(g) for g in groups)
    else:
        groups_str = ""

    # EllipticCurvePointFormats
    epf_ext = _ext(ch, 0x000B)
    if epf_ext:
        formats_str = "-".join(str(f) for f in epf_ext.parsed.get("formats", []))
    else:
        formats_str = ""

    ja3 = f"{version},{ciphers_str},{exts_str},{groups_str},{formats_str}"
    ja3_hash = hashlib.md5(ja3.encode()).hexdigest()
    return ja3, ja3_hash
