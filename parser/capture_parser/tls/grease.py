"""GREASE detection helpers (RFC 8701)."""


def is_grease_u16(v: int) -> bool:
    """Return True if v is one of the 16 GREASE 16-bit values."""
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def grease_positions(lst: list[int]) -> list[int]:
    return [i for i, v in enumerate(lst) if is_grease_u16(v)]


def filter_grease(lst: list[int]) -> list[int]:
    return [v for v in lst if not is_grease_u16(v)]


def any_grease(*lists: list[int]) -> bool:
    return any(is_grease_u16(v) for lst in lists for v in lst)
