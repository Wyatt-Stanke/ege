"""ClientHello → structured data for fingerprinting.

This module consolidates the ClientHello into a single rich dict that
downstream fingerprinters consume.  It also resolves IANA names and
records GREASE positions.
"""
import hashlib

from .records import ClientHello, ParsedExtension
from .grease import grease_positions, filter_grease, any_grease
from .registry import (
    name_cipher, name_extension, name_group, name_sigalg, name_cert_compression,
)


def _ext(ch: ClientHello, ext_type: int) -> ParsedExtension | None:
    for e in ch.extensions:
        if e.ext_type == ext_type:
            return e
    return None


def _ext_parsed(ch: ClientHello, ext_type: int) -> dict:
    e = _ext(ch, ext_type)
    return e.parsed if e else {}


def build_tls_info(ch: ClientHello) -> dict:
    """Build the `tls` block from a parsed ClientHello."""

    ext_types = [e.ext_type for e in ch.extensions]

    # ---- Ciphers ----
    cs = ch.cipher_suites
    tls_ciphers = {
        "list": [f"0x{v:04x}" for v in cs],
        "list_named": [name_cipher(v) for v in cs],
        "grease_positions": grease_positions(cs),
    }

    # ---- Extensions ----
    tls_extensions = {
        "list": [f"0x{v:04x}" for v in ext_types],
        "list_named": [name_extension(v) for v in ext_types],
        "grease_positions": grease_positions(ext_types),
        # order/permuted are filled in by variation.py at the session level
        "order": "fixed",
        "permuted_seen_orders": 1,
    }

    # ---- Supported groups ----
    sg_parsed = _ext_parsed(ch, 0x000A)
    sg_list = sg_parsed.get("groups", [])
    tls_supported_groups = {
        "list": [f"0x{v:04x}" for v in sg_list],
        "list_named": [name_group(v) for v in sg_list],
        "grease_positions": grease_positions(sg_list),
    }

    # ---- Signature algorithms ----
    sa_parsed = _ext_parsed(ch, 0x000D)
    sa_list = sa_parsed.get("algorithms", [])
    tls_sig_algs = {
        "list": [f"0x{v:04x}" for v in sa_list],
        "list_named": [name_sigalg(v) for v in sa_list],
    }

    # ---- EC point formats ----
    epf_parsed = _ext_parsed(ch, 0x000B)
    epf_list = epf_parsed.get("formats", [])
    tls_ec_point = {"list": epf_list}

    # ---- Key share ----
    ks_parsed = _ext_parsed(ch, 0x0033)
    ks_entries = ks_parsed.get("entries", [])
    ks_groups = [e["group"] for e in ks_entries]
    tls_key_share = {
        "list": [f"0x{v:04x}" for v in ks_groups],
        "list_named": [name_group(v) for v in ks_groups],
        "grease_positions": grease_positions(ks_groups),
    }

    # ---- Supported versions ----
    sv_parsed = _ext_parsed(ch, 0x002B)
    sv_list = sv_parsed.get("versions", [])
    tls_supported_versions = {
        "list": [f"0x{v:04x}" for v in sv_list],
        "grease_positions": grease_positions(sv_list),
    }

    # ---- PSK key exchange modes ----
    pskm_parsed = _ext_parsed(ch, 0x002D)
    tls_psk_modes = {"list": pskm_parsed.get("modes", [])}

    # ---- ALPN ----
    alpn_parsed = _ext_parsed(ch, 0x0010)
    tls_alpn = {"list": alpn_parsed.get("protocols", [])}

    # ---- Cert compression ----
    cc_parsed = _ext_parsed(ch, 0x001B)
    cc_algs = cc_parsed.get("algorithms", [])
    tls_cert_compression = {
        "list": cc_algs,
        "list_named": [name_cert_compression(v) for v in cc_algs],
    }

    # ---- Simple boolean presence fields ----
    record_size_limit = _ext_parsed(ch, 0x001C).get("limit")

    return {
        "record_version": f"0x{ch.record_version:04x}",
        "client_hello_version": f"0x{ch.legacy_version:04x}",
        "ciphers": tls_ciphers,
        "extensions": tls_extensions,
        "supported_groups": tls_supported_groups,
        "signature_algorithms": tls_sig_algs,
        "ec_point_formats": tls_ec_point,
        "key_share_groups": tls_key_share,
        "supported_versions": tls_supported_versions,
        "psk_key_exchange_modes": tls_psk_modes,
        "alpn": tls_alpn,
        "cert_compression_algorithms": tls_cert_compression,
        "record_size_limit": record_size_limit,
        # presence flags
        "compress_certificate_present": _ext(ch, 0x001B) is not None,
        "extended_master_secret_present": _ext(ch, 0x0017) is not None,
        "session_ticket_present": _ext(ch, 0x0023) is not None,
        "encrypted_client_hello_present": _ext(ch, 0xFE0D) is not None,
        "application_settings_present": (_ext(ch, 0x4469) is not None or _ext(ch, 0x44CD) is not None),
        "renegotiation_info_present": _ext(ch, 0xFF01) is not None,
        "padding_present": _ext(ch, 0x0015) is not None,
    }
