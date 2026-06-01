"""HTTP/2 frame walker + HPACK extraction.

Produces an H2Info dataclass from decrypted_inbound.bin content.
"""
import hashlib
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Frame type constants
FRAME_DATA           = 0x00
FRAME_HEADERS        = 0x01
FRAME_PRIORITY       = 0x02
FRAME_RST_STREAM     = 0x03
FRAME_SETTINGS       = 0x04
FRAME_PUSH_PROMISE   = 0x05
FRAME_PING           = 0x06
FRAME_GOAWAY         = 0x07
FRAME_WINDOW_UPDATE  = 0x08
FRAME_CONTINUATION   = 0x09
FRAME_PRIORITY_UPDATE = 0x10

# HEADERS flags
FLAG_END_STREAM  = 0x01
FLAG_END_HEADERS = 0x04
FLAG_PADDED      = 0x08
FLAG_PRIORITY    = 0x20

# Pseudo-header → single char (Akamai convention)
PSEUDO_MAP = {
    ":method":    "m",
    ":authority": "a",
    ":scheme":    "s",
    ":path":      "p",
}


@dataclass
class H2Info:
    settings: list = field(default_factory=list)          # [(id, value), …] in order
    window_update: int | None = None                       # first conn-level increment
    priority_frames: list = field(default_factory=list)   # [(stream, dep, weight, excl), …]
    uses_extensible_priorities: bool = False
    pseudo_header_order: list = field(default_factory=list)   # ["m","a","s","p"]
    request_headers: list = field(default_factory=list)        # non-pseudo header names
    first_settings_frame_hex: str = ""
    first_headers_frame_hex: str = ""


def _read_frame(data: bytes, off: int) -> tuple[int, int, int, bytes, int] | None:
    """Read one frame at offset.  Returns (length, ftype, flags, stream_id, payload, next_off)."""
    if off + 9 > len(data):
        return None
    length = (data[off] << 16) | (data[off + 1] << 8) | data[off + 2]
    ftype = data[off + 3]
    flags = data[off + 4]
    stream_id = int.from_bytes(data[off + 5:off + 9], "big") & 0x7FFFFFFF
    payload_start = off + 9
    payload_end = payload_start + length
    if payload_end > len(data):
        return None
    return ftype, flags, stream_id, data[payload_start:payload_end], payload_end


def _parse_hpack(block: bytes) -> list[tuple[str, str]] | None:
    """Decode HPACK block.  Returns [(name, value), …] or None on error."""
    try:
        import hpack
        decoder = hpack.Decoder()
        return decoder.decode(block)
    except Exception as exc:
        logger.warning("HPACK decode failed: %s", exc)
        return None


def parse_h2(data: bytes) -> H2Info:
    """Parse decrypted_inbound.bin content for an h2 connection."""
    info = H2Info()

    # Skip preface
    off = 0
    if data.startswith(H2_PREFACE):
        off = len(H2_PREFACE)

    headers_done = False

    while not headers_done:
        result = _read_frame(data, off)
        if result is None:
            break
        ftype, flags, stream_id, payload, off = result

        if ftype == FRAME_SETTINGS and not info.first_settings_frame_hex:
            # Record hex of the full raw frame bytes
            frame_raw = data[off - 9 - len(payload):off]
            info.first_settings_frame_hex = frame_raw.hex()

            # Parse setting pairs: (uint16 id, uint32 value)
            for i in range(0, len(payload) - 5, 6):
                setting_id = int.from_bytes(payload[i:i + 2], "big")
                setting_val = int.from_bytes(payload[i + 2:i + 6], "big")
                info.settings.append((setting_id, setting_val))

        elif ftype == FRAME_WINDOW_UPDATE and stream_id == 0 and info.window_update is None:
            if len(payload) >= 4:
                info.window_update = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF

        elif ftype == FRAME_PRIORITY and not headers_done:
            if len(payload) >= 5:
                dep_and_excl = int.from_bytes(payload[:4], "big")
                exclusive = (dep_and_excl >> 31) & 1
                dep = dep_and_excl & 0x7FFFFFFF
                weight = payload[4] + 1  # weight is stored as weight-1
                info.priority_frames.append((stream_id, dep, weight, exclusive))

        elif ftype == FRAME_PRIORITY_UPDATE:
            info.uses_extensible_priorities = True

        elif ftype == FRAME_HEADERS:
            # Record raw frame hex
            frame_start = off - 9 - len(payload)
            if not info.first_headers_frame_hex:
                info.first_headers_frame_hex = data[frame_start:off].hex()

            # Extract HPACK block (strip padding and priority prefix if present)
            p = payload
            pad_len = 0
            if flags & FLAG_PADDED:
                pad_len = p[0]
                p = p[1:]
            if flags & FLAG_PRIORITY:
                p = p[5:]  # skip 4-byte dep + 1-byte weight
            if pad_len:
                p = p[:-pad_len]

            headers = _parse_hpack(p)
            if headers is not None:
                for name, _ in headers:
                    if name.startswith(":"):
                        char = PSEUDO_MAP.get(name, name)
                        if char not in info.pseudo_header_order:
                            info.pseudo_header_order.append(char)
                    else:
                        info.request_headers.append(name)

            headers_done = True

    return info
