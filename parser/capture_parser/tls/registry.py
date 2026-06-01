"""IANA-derived name maps for TLS parameters.

Sources:
  https://www.iana.org/assignments/tls-parameters/
Covers common values used by Chrome, Firefox, and Safari.
Unknown IDs format as "unknown_0x1234".
"""

from typing import Union


def _u(val: int) -> str:
    return f"unknown_0x{val:04x}"


def _lookup(table: dict, val: int) -> str:
    return table.get(val, _u(val))


# ---------------------------------------------------------------------------
# Cipher suites
# ---------------------------------------------------------------------------

CIPHER_SUITES: dict[int, str] = {
    # TLS 1.3
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    # ECDHE-ECDSA
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    # ECDHE-RSA
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    # RSA
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    # DHE-RSA
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    # PSK
    0x00A8: "TLS_PSK_WITH_AES_128_GCM_SHA256",
    0x00A9: "TLS_PSK_WITH_AES_256_GCM_SHA384",
    0xC0AC: "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
    # NULL / empty
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    # SCSV
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0x5600: "TLS_FALLBACK_SCSV",
}


# ---------------------------------------------------------------------------
# Extension types
# ---------------------------------------------------------------------------

EXTENSION_TYPES: dict[int, str] = {
    0x0000: "server_name",
    0x0001: "max_fragment_length",
    0x0002: "client_certificate_url",
    0x0003: "trusted_ca_keys",
    0x0004: "truncated_hmac",
    0x0005: "status_request",
    0x0006: "user_mapping",
    0x0007: "client_authz",
    0x0008: "server_authz",
    0x0009: "cert_type",
    0x000A: "supported_groups",
    0x000B: "ec_point_formats",
    0x000C: "srp",
    0x000D: "signature_algorithms",
    0x000E: "use_srtp",
    0x000F: "heartbeat",
    0x0010: "application_layer_protocol_negotiation",
    0x0011: "status_request_v2",
    0x0012: "signed_certificate_timestamp",
    0x0013: "client_certificate_type",
    0x0014: "server_certificate_type",
    0x0015: "padding",
    0x0016: "encrypt_then_mac",
    0x0017: "extended_master_secret",
    0x0018: "token_binding",
    0x0019: "cached_info",
    0x001A: "tls_lts",
    0x001B: "compress_certificate",
    0x001C: "record_size_limit",
    0x001D: "pwd_protect",
    0x001E: "pwd_clear",
    0x001F: "password_salt",
    0x0023: "session_ticket",
    0x0029: "pre_shared_key",
    0x002A: "early_data",
    0x002B: "supported_versions",
    0x002C: "cookie",
    0x002D: "psk_key_exchange_modes",
    0x002F: "certificate_authorities",
    0x0030: "oid_filters",
    0x0031: "post_handshake_auth",
    0x0032: "signature_algorithms_cert",
    0x0033: "key_share",
    0x0039: "quic_transport_parameters",
    0x003C: "tls_flags",
    0x4469: "application_settings",
    0x44CD: "application_settings",   # Chrome draft codepoint (ALPS)
    0xFE0D: "encrypted_client_hello",
    0xFF01: "renegotiation_info",
}


# ---------------------------------------------------------------------------
# Supported groups (named curves)
# ---------------------------------------------------------------------------

SUPPORTED_GROUPS: dict[int, str] = {
    0x0001: "sect163k1",
    0x0002: "sect163r1",
    0x0003: "sect163r2",
    0x0006: "sect233k1",
    0x0007: "sect233r1",
    0x0009: "sect283k1",
    0x000A: "sect283r1",
    0x000B: "sect409k1",
    0x000C: "sect409r1",
    0x000D: "sect571k1",
    0x000E: "sect571r1",
    0x000F: "secp160k1",
    0x0010: "secp160r1",
    0x0011: "secp160r2",
    0x0012: "secp192k1",
    0x0013: "secp192r1",
    0x0014: "secp224k1",
    0x0015: "secp224r1",
    0x0016: "secp256k1",
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
    0x0103: "ffdhe6144",
    0x0104: "ffdhe8192",
    0x6399: "x25519_kyber768draft00",
    0x639A: "X25519MLKEM768",
    0x6F00: "SecP256r1MLKEM768",
    0x11EB: "SecP256r1MLKEM768",
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
}


# ---------------------------------------------------------------------------
# Signature algorithms (SignatureScheme)
# ---------------------------------------------------------------------------

SIGNATURE_ALGORITHMS: dict[int, str] = {
    # RSASSA-PKCS1-v1_5
    0x0201: "rsa_pkcs1_sha1",
    0x0401: "rsa_pkcs1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    # ECDSA
    0x0203: "ecdsa_sha1",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512",
    # RSASSA-PSS RSAE
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    # EdDSA
    0x0807: "ed25519",
    0x0808: "ed448",
    # RSASSA-PSS PSS
    0x0809: "rsa_pss_pss_sha256",
    0x080A: "rsa_pss_pss_sha384",
    0x080B: "rsa_pss_pss_sha512",
    # Legacy
    0x0101: "rsa_md5",
    0x0301: "rsa_sha224",
    0x0303: "ecdsa_sha224",
    0x0402: "dsa_sha256",
    0x0502: "dsa_sha384",
    0x0602: "dsa_sha512",
}


# ---------------------------------------------------------------------------
# Certificate compression algorithms
# ---------------------------------------------------------------------------

CERT_COMPRESSION: dict[int, str] = {
    1: "zlib",
    2: "brotli",
    3: "zstd",
}


# ---------------------------------------------------------------------------
# H2 SETTINGS identifiers
# ---------------------------------------------------------------------------

H2_SETTINGS: dict[int, str] = {
    0x01: "HEADER_TABLE_SIZE",
    0x02: "ENABLE_PUSH",
    0x03: "MAX_CONCURRENT_STREAMS",
    0x04: "INITIAL_WINDOW_SIZE",
    0x05: "MAX_FRAME_SIZE",
    0x06: "MAX_HEADER_LIST_SIZE",
    0x08: "ENABLE_CONNECT_PROTOCOL",
    0x09: "NO_RFC7540_PRIORITIES",
}


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

def name_cipher(v: int) -> str:
    return _lookup(CIPHER_SUITES, v)


def name_extension(v: int) -> str:
    return _lookup(EXTENSION_TYPES, v)


def name_group(v: int) -> str:
    return _lookup(SUPPORTED_GROUPS, v)


def name_sigalg(v: int) -> str:
    return _lookup(SIGNATURE_ALGORITHMS, v)


def name_cert_compression(v: int) -> str:
    return _lookup(CERT_COMPRESSION, v)


def name_h2_setting(v: int) -> str:
    return _lookup(H2_SETTINGS, v)
