"""Peetprint-style structured fingerprint dict.

This is a human-readable structured representation of the ClientHello,
mirroring what peet.ws displays.  We lift fields from the tls_info dict
built by clienthello.py.
"""

from ..tls.records import ClientHello
from ..tls.clienthello import build_tls_info


def compute_peetprint(ch: ClientHello) -> dict:
    """Return a flat structured dict matching peet.ws fields."""
    info = build_tls_info(ch)

    return {
        "TLSVersion": info["client_hello_version"],
        "Ciphers": info["ciphers"]["list"],
        "Extensions": info["extensions"]["list"],
        "EllipticCurves": info["supported_groups"]["list"],
        "EllipticCurvePointFormats": info["ec_point_formats"]["list"],
        "SupportedVersions": info["supported_versions"]["list"],
        "SignatureAlgorithms": info["signature_algorithms"]["list"],
        "KeyShareCurves": info["key_share_groups"]["list"],
        "PSKKeyExchangeModes": info["psk_key_exchange_modes"]["list"],
        "ALPN": info["alpn"]["list"],
        "CertCompression": info["cert_compression_algorithms"]["list_named"],
        "ExtendedMasterSecret": info["extended_master_secret_present"],
        "SessionTicket": info["session_ticket_present"],
        "EncryptedClientHello": info["encrypted_client_hello_present"],
        "ALPS": info["application_settings_present"],
        "RenegotiationInfo": info["renegotiation_info_present"],
        "Padding": info["padding_present"],
        "RecordSizeLimit": info["record_size_limit"],
    }
