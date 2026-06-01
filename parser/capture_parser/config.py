"""Build the curl-impersonate-style declarative config block."""

from .tls.records import ClientHello
from .tls.grease import filter_grease, any_grease
from .tls.registry import name_cipher, name_group, name_sigalg, name_cert_compression
from .h2.frames import H2Info


def _ext(ch: ClientHello, ext_type: int):
    for e in ch.extensions:
        if e.ext_type == ext_type:
            return e
    return None


def _ext_parsed(ch: ClientHello, ext_type: int) -> dict:
    e = _ext(ch, ext_type)
    return e.parsed if e else {}


def build_config(
    ch: ClientHello,
    h2: H2Info | None,
    permute_extensions: bool,
    extension_order: list[int] | None,
) -> dict:
    """
    Build the declarative config block.

    permute_extensions: True if Chrome extension permutation detected.
    extension_order: raw (int) list of non-GREASE extension types in send order,
                     or None when permute_extensions is True.
    """

    # Ciphers (colon-joined IANA names, GREASE filtered)
    ciphers_clean = filter_grease(ch.cipher_suites)
    ciphers_str = ":".join(name_cipher(c) for c in ciphers_clean)

    # Curves (colon-joined, GREASE filtered)
    sg = _ext_parsed(ch, 0x000A).get("groups", [])
    curves_str = ":".join(name_group(g) for g in filter_grease(sg))

    # Signature algorithms (comma-joined)
    sa = _ext_parsed(ch, 0x000D).get("algorithms", [])
    sig_hashes_str = ",".join(name_sigalg(a) for a in sa)

    # Key share curves (colon-joined, GREASE filtered)
    ks_entries = _ext_parsed(ch, 0x0033).get("entries", [])
    ks_groups = filter_grease([e["group"] for e in ks_entries])
    key_share_str = ":".join(name_group(g) for g in ks_groups)

    # ALPN (comma-joined)
    alpn_list = _ext_parsed(ch, 0x0010).get("protocols", [])
    alpn_str = ",".join(alpn_list)

    # Cert compression
    cc_algs = _ext_parsed(ch, 0x001B).get("algorithms", [])
    cert_compression_str = ",".join(name_cert_compression(a) for a in cc_algs) or None

    # Extension order: comma-joined hex, or null if permuted
    if permute_extensions or extension_order is None:
        tls_ext_order = None
    else:
        tls_ext_order = ",".join(f"0x{v:04x}" for v in extension_order)

    # GREASE: any GREASE in ciphers, extensions, groups, key_share, versions?
    ext_types = [e.ext_type for e in ch.extensions]
    sv = _ext_parsed(ch, 0x002B).get("versions", [])
    tls_grease = any_grease(
        ch.cipher_suites, ext_types, sg,
        [e["group"] for e in ks_entries], sv
    )

    # EC point formats
    epf = _ext_parsed(ch, 0x000B).get("formats", [])
    ec_point_formats_str = ",".join(str(f) for f in epf) if epf else None

    # H2 settings string
    if h2 and h2.settings:
        h2_settings_str = ";".join(f"{k}:{v}" for k, v in h2.settings)
        h2_window = h2.window_update
        h2_pseudo = ",".join(h2.pseudo_header_order) if h2.pseudo_header_order else None
        # PRIORITY stream weight (old-style); use first PRIORITY frame's weight if any
        h2_stream_weight = h2.priority_frames[0][2] if h2.priority_frames else None
    else:
        h2_settings_str = None
        h2_window = None
        h2_pseudo = None
        h2_stream_weight = None

    return {
        "_comment": "Declarative config in curl-impersonate-compatible vocabulary",
        "ciphers": ciphers_str,
        "curves": curves_str,
        "sig_hashes": sig_hashes_str,
        "key_share_curves": key_share_str,
        "alpn": alpn_str,
        "cert_compression": cert_compression_str,
        "tls_extension_order": tls_ext_order,
        "tls_permute_extensions": permute_extensions,
        "tls_grease": tls_grease,
        "ec_point_formats": ec_point_formats_str,
        "session_ticket": _ext(ch, 0x0023) is not None,
        "extended_master_secret": _ext(ch, 0x0017) is not None,
        "compress_certificate": _ext(ch, 0x001B) is not None,
        "application_settings": (_ext(ch, 0x4469) is not None or _ext(ch, 0x44CD) is not None),
        "record_size_limit": _ext_parsed(ch, 0x001C).get("limit"),
        "http2_settings": h2_settings_str,
        "http2_window_update": h2_window,
        "http2_stream_weight": h2_stream_weight,
        "http2_pseudo_headers_order": h2_pseudo,
    }
