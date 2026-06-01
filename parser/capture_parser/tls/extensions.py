"""Extension-level parsers.

Each parser receives the raw extension data bytes (after the type+length
header has been stripped) and returns a dict of parsed fields.
Unknown extensions return {"hex": data.hex()}.
"""


def _u16(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 2], "big")


def _u8(b: bytes, off: int) -> int:
    return b[off]


# ---------------------------------------------------------------------------
# Individual extension parsers
# ---------------------------------------------------------------------------

def parse_server_name(data: bytes) -> dict:
    """0x0000 - server_name."""
    if len(data) < 2:
        return {}
    list_len = _u16(data, 0)
    i = 2
    names = []
    end = 2 + list_len
    while i + 3 <= end:
        name_type = _u8(data, i)
        name_len = _u16(data, i + 1)
        i += 3
        if i + name_len > len(data):
            break
        if name_type == 0:  # host_name
            names.append(data[i:i + name_len].decode(errors="replace"))
        i += name_len
    return {"hostnames": names, "sni": names[0] if names else None}


def parse_status_request(data: bytes) -> dict:
    """0x0005 - status_request."""
    return {"present": True, "length": len(data)}


def parse_supported_groups(data: bytes) -> dict:
    """0x000a - supported_groups."""
    if len(data) < 2:
        return {"groups": []}
    list_len = _u16(data, 0)
    groups = []
    for off in range(2, 2 + list_len, 2):
        if off + 2 > len(data):
            break
        groups.append(_u16(data, off))
    return {"groups": groups}


def parse_ec_point_formats(data: bytes) -> dict:
    """0x000b - ec_point_formats."""
    if not data:
        return {"formats": []}
    count = _u8(data, 0)
    formats = list(data[1:1 + count])
    return {"formats": formats}


def parse_signature_algorithms(data: bytes) -> dict:
    """0x000d - signature_algorithms."""
    if len(data) < 2:
        return {"algorithms": []}
    list_len = _u16(data, 0)
    algs = []
    for off in range(2, 2 + list_len, 2):
        if off + 2 > len(data):
            break
        algs.append(_u16(data, off))
    return {"algorithms": algs}


def parse_alpn(data: bytes) -> dict:
    """0x0010 - application_layer_protocol_negotiation."""
    if len(data) < 2:
        return {"protocols": []}
    list_len = _u16(data, 0)
    protocols = []
    i = 2
    end = 2 + list_len
    while i < end and i < len(data):
        plen = _u8(data, i)
        i += 1
        if i + plen > len(data):
            break
        protocols.append(data[i:i + plen].decode(errors="replace"))
        i += plen
    return {"protocols": protocols}


def parse_signed_certificate_timestamp(data: bytes) -> dict:
    """0x0012 - signed_certificate_timestamp."""
    return {"present": True}


def parse_padding(data: bytes) -> dict:
    """0x0015 - padding."""
    return {"present": True, "length": len(data)}


def parse_encrypt_then_mac(data: bytes) -> dict:
    """0x0016 - encrypt_then_mac."""
    return {"present": True}


def parse_extended_master_secret(data: bytes) -> dict:
    """0x0017 - extended_master_secret."""
    return {"present": True}


def parse_compress_certificate(data: bytes) -> dict:
    """0x001b - compress_certificate."""
    if len(data) < 1:
        return {"algorithms": []}
    count = _u8(data, 0)
    algs = []
    for off in range(1, 1 + count * 2, 2):
        if off + 2 > len(data):
            break
        algs.append(_u16(data, off))
    return {"algorithms": algs}


def parse_record_size_limit(data: bytes) -> dict:
    """0x001c - record_size_limit."""
    if len(data) < 2:
        return {"limit": None}
    return {"limit": _u16(data, 0)}


def parse_session_ticket(data: bytes) -> dict:
    """0x0023 - session_ticket."""
    return {"present": True, "length": len(data)}


def parse_pre_shared_key(data: bytes) -> dict:
    """0x0029 - pre_shared_key (last extension, don't parse body)."""
    return {"present": True}


def parse_supported_versions(data: bytes) -> dict:
    """0x002b - supported_versions."""
    if len(data) < 1:
        return {"versions": []}
    # ClientHello: list of uint16 prefixed by uint8 length-in-bytes
    list_len = _u8(data, 0)
    versions = []
    for off in range(1, 1 + list_len, 2):
        if off + 2 > len(data):
            break
        versions.append(_u16(data, off))
    return {"versions": versions}


def parse_psk_key_exchange_modes(data: bytes) -> dict:
    """0x002d - psk_key_exchange_modes."""
    if not data:
        return {"modes": []}
    count = _u8(data, 0)
    modes = list(data[1:1 + count])
    return {"modes": modes}


def parse_key_share(data: bytes) -> dict:
    """0x0033 - key_share (ClientHello variant)."""
    if len(data) < 2:
        return {"entries": []}
    list_len = _u16(data, 0)
    entries = []
    i = 2
    end = 2 + list_len
    while i + 4 <= end and i + 4 <= len(data):
        group = _u16(data, i)
        key_len = _u16(data, i + 2)
        entries.append({"group": group, "key_length": key_len})
        i += 4 + key_len
    return {"entries": entries}


def parse_application_settings(data: bytes) -> dict:
    """0x4469 - application_settings (ALPS)."""
    if len(data) < 2:
        return {"protocols": []}
    list_len = _u16(data, 0)
    protocols = []
    i = 2
    end = 2 + list_len
    while i < end and i < len(data):
        plen = _u8(data, i)
        i += 1
        if i + plen > len(data):
            break
        protocols.append(data[i:i + plen].decode(errors="replace"))
        i += plen
    return {"protocols": protocols}


def parse_encrypted_client_hello(data: bytes) -> dict:
    """0xfe0d - encrypted_client_hello."""
    return {"present": True, "length": len(data)}


def parse_renegotiation_info(data: bytes) -> dict:
    """0xff01 - renegotiation_info."""
    return {"present": True, "length": len(data)}


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

_PARSERS = {
    0x0000: parse_server_name,
    0x0005: parse_status_request,
    0x000A: parse_supported_groups,
    0x000B: parse_ec_point_formats,
    0x000D: parse_signature_algorithms,
    0x0010: parse_alpn,
    0x0012: parse_signed_certificate_timestamp,
    0x0015: parse_padding,
    0x0016: parse_encrypt_then_mac,
    0x0017: parse_extended_master_secret,
    0x001B: parse_compress_certificate,
    0x001C: parse_record_size_limit,
    0x0023: parse_session_ticket,
    0x0029: parse_pre_shared_key,
    0x002B: parse_supported_versions,
    0x002D: parse_psk_key_exchange_modes,
    0x0033: parse_key_share,
    0x4469: parse_application_settings,
    0x44CD: parse_application_settings,   # Chrome draft codepoint (ALPS)
    0xFE0D: parse_encrypted_client_hello,
    0xFF01: parse_renegotiation_info,
}


def parse_extension(ext_type: int, data: bytes) -> dict:
    """Dispatch to the right parser, fall back to raw hex for unknowns."""
    parser = _PARSERS.get(ext_type)
    if parser is not None:
        try:
            return parser(data)
        except Exception:
            pass
    return {"hex": data.hex()}
