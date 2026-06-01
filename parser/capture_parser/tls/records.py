"""TLS record layer iterator and ClientHello extractor."""
from dataclasses import dataclass, field
from typing import Iterator

from .extensions import parse_extension
from .registry import name_cipher, name_extension, name_group, name_sigalg, name_cert_compression


# ---------------------------------------------------------------------------
# Record iterator
# ---------------------------------------------------------------------------

def iter_records(data: bytes) -> Iterator[tuple[int, int, bytes, int]]:
    """Yield (content_type, version, payload, record_start_offset)."""
    i = 0
    while i + 5 <= len(data):
        ct = data[i]
        version = int.from_bytes(data[i + 1:i + 3], "big")
        length = int.from_bytes(data[i + 3:i + 5], "big")
        start = i
        i += 5
        if i + length > len(data):
            break
        yield ct, version, data[i:i + length], start
        i += length


def extract_client_hello_bytes(raw: bytes) -> tuple[bytes, int, bytes]:
    """
    Scan raw_inbound.bin and return:
      (ch_body, outer_record_version, raw_record_bytes)

    ch_body: the ClientHello message body (after the 4-byte handshake header).
    raw_record_bytes: the full TLS record(s) containing the ClientHello
                     (for hex output).

    Returns (b"", 0x0301, b"") if no ClientHello is found.
    """
    hs_buf = bytearray()
    outer_version = 0x0301
    record_bytes = bytearray()

    for ct, version, payload, rec_start in iter_records(raw):
        if ct != 22:  # not Handshake
            if hs_buf:
                break
            continue

        if not hs_buf:
            outer_version = version

        hs_buf.extend(payload)
        record_end = rec_start + 5 + len(payload)
        record_bytes.extend(raw[rec_start:record_end])

        # Check if we have a complete handshake message
        if len(hs_buf) < 4:
            continue
        msg_type = hs_buf[0]
        msg_len = (hs_buf[1] << 16) | (hs_buf[2] << 8) | hs_buf[3]
        if msg_type == 0x01 and len(hs_buf) >= 4 + msg_len:
            return bytes(hs_buf[4:4 + msg_len]), outer_version, bytes(record_bytes)

    return b"", outer_version, b""


# ---------------------------------------------------------------------------
# ClientHello dataclass
# ---------------------------------------------------------------------------

@dataclass
class ParsedExtension:
    ext_type: int
    raw_data: bytes
    parsed: dict


@dataclass
class ClientHello:
    record_version: int
    legacy_version: int
    random: bytes
    session_id: bytes
    cipher_suites: list   # int list, in order, GREASE included
    compression_methods: list
    extensions: list      # ParsedExtension list, in order
    raw_bytes: bytes      # full TLS record bytes (for hex output)


# ---------------------------------------------------------------------------
# ClientHello parser
# ---------------------------------------------------------------------------

def parse_client_hello(raw: bytes) -> ClientHello:
    """
    Parse raw_inbound.bin.  Returns a ClientHello or raises ValueError.
    """
    ch_body, record_version, raw_bytes = extract_client_hello_bytes(raw)
    if not ch_body:
        raise ValueError("No ClientHello found in raw bytes")

    off = 0

    # legacy_version (2 bytes)
    if off + 2 > len(ch_body):
        raise ValueError("Truncated ClientHello: no legacy_version")
    legacy_version = int.from_bytes(ch_body[off:off + 2], "big")
    off += 2

    # random (32 bytes)
    if off + 32 > len(ch_body):
        raise ValueError("Truncated ClientHello: no random")
    random_bytes = ch_body[off:off + 32]
    off += 32

    # session_id
    if off + 1 > len(ch_body):
        raise ValueError("Truncated ClientHello: no session_id_len")
    sid_len = ch_body[off]
    off += 1
    session_id = ch_body[off:off + sid_len]
    off += sid_len

    # cipher_suites
    if off + 2 > len(ch_body):
        raise ValueError("Truncated ClientHello: no cipher_suites_len")
    cs_len = int.from_bytes(ch_body[off:off + 2], "big")
    off += 2
    cipher_suites = []
    for i in range(0, cs_len, 2):
        if off + 2 > len(ch_body):
            break
        cipher_suites.append(int.from_bytes(ch_body[off:off + 2], "big"))
        off += 2

    # compression_methods
    if off + 1 > len(ch_body):
        raise ValueError("Truncated ClientHello: no compression_methods_len")
    cm_len = ch_body[off]
    off += 1
    compression_methods = list(ch_body[off:off + cm_len])
    off += cm_len

    # extensions
    extensions = []
    if off + 2 <= len(ch_body):
        exts_len = int.from_bytes(ch_body[off:off + 2], "big")
        off += 2
        exts_end = off + exts_len
        while off + 4 <= exts_end and off + 4 <= len(ch_body):
            ext_type = int.from_bytes(ch_body[off:off + 2], "big")
            ext_len = int.from_bytes(ch_body[off + 2:off + 4], "big")
            off += 4
            ext_data = ch_body[off:off + ext_len]
            off += ext_len
            parsed = parse_extension(ext_type, ext_data)
            extensions.append(ParsedExtension(
                ext_type=ext_type,
                raw_data=ext_data,
                parsed=parsed,
            ))

    return ClientHello(
        record_version=record_version,
        legacy_version=legacy_version,
        random=random_bytes,
        session_id=session_id,
        cipher_suites=cipher_suites,
        compression_methods=compression_methods,
        extensions=extensions,
        raw_bytes=raw_bytes,
    )
