"""Akamai HTTP/2 fingerprint string builder."""
import hashlib

from .frames import H2Info


def build_akamai_string(info: H2Info) -> str:
    """
    Format:
      <SETTINGS>|<WINDOW_UPDATE>|<PRIORITY>|<HEADER_ORDER>

    SETTINGS  : "id:val;id:val;…" in received order, IDs as decimal
    WINDOW_UPDATE : decimal increment, or "00" if none
    PRIORITY  : "0" if none; "stream:dep:weight:exclusive,…" otherwise
    HEADER_ORDER  : "m,a,s,p" (pseudo-header chars)
    """
    settings_part = ";".join(f"{k}:{v}" for k, v in info.settings)

    wu = "00" if info.window_update is None else str(info.window_update)

    if info.priority_frames:
        prio_parts = []
        for stream, dep, weight, excl in info.priority_frames:
            prio_parts.append(f"{stream}:{dep}:{weight}:{excl}")
        prio_part = ",".join(prio_parts)
    else:
        prio_part = "0"

    header_order = ",".join(info.pseudo_header_order)

    return f"{settings_part}|{wu}|{prio_part}|{header_order}"


def akamai_hash(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()
