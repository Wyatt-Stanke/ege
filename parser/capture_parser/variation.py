from collections import Counter

from .tls.records import ClientHello
from .tls.grease import filter_grease, is_grease_u16


PRE_SHARED_KEY = 0x0029
EARLY_DATA = 0x002A
PADDING = 0x0015
COOKIE = 0x002C
ENCRYPTED_CLIENT_HELLO = 0xFE0D

VOLATILE_EXT_TYPES = frozenset({
    PRE_SHARED_KEY,
    EARLY_DATA,
    PADDING,
    COOKIE,
    ENCRYPTED_CLIENT_HELLO,  
})

ORDER_EXCLUDED_TYPES = frozenset({PRE_SHARED_KEY})


# --------------------------------------------------------------------------- #
# Extractors
# --------------------------------------------------------------------------- #
def _ext_types(ch: ClientHello, filter_g: bool = True) -> list[int]:
    """Ordered list of extension types (GREASE removed by default)."""
    types = [e.ext_type for e in ch.extensions]
    return filter_grease(types) if filter_g else types


def _sg_list(ch: ClientHello) -> list[int]:
    for e in ch.extensions:
        if e.ext_type == 0x000A:  # supported_groups
            return e.parsed.get("groups", [])
    return []


def _ks_groups(ch: ClientHello) -> list[int]:
    for e in ch.extensions:
        if e.ext_type == 0x0033:  # key_share
            return filter_grease(
                [entry["group"] for entry in e.parsed.get("entries", [])]
            )
    return []


def _sig_algs(ch: ClientHello) -> tuple:
    for e in ch.extensions:
        if e.ext_type == 0x000D:  # signature_algorithms
            return tuple(e.parsed.get("algorithms", []))
    return ()


def _alpn(ch: ClientHello) -> tuple:
    for e in ch.extensions:
        if e.ext_type == 0x0010:  # ALPN
            return tuple(e.parsed.get("protocols", []))
    return ()


def _cipher_multiset(ch: ClientHello) -> frozenset:
    return frozenset(Counter(filter_grease(ch.cipher_suites)).items())


def _all_u16_values(ch: ClientHello) -> list[int]:
    """Every u16 codepoint that could carry a GREASE value."""
    vals = list(ch.cipher_suites)
    vals += [e.ext_type for e in ch.extensions]
    vals += _sg_list(ch)
    vals += [entry.get("group") for e in ch.extensions
             if e.ext_type == 0x0033
             for entry in e.parsed.get("entries", [])
             if entry.get("group") is not None]
    return vals


def _has_grease(ch: ClientHello) -> bool:
    return any(is_grease_u16(v) for v in _all_u16_values(ch))


def _detect_extension_permutation(
    conns: list[tuple[str, ClientHello]]
) -> tuple[bool, list[int] | None, dict]:
    if len(conns) < 2:
        return False, (
            _ext_types(conns[0][1]) if conns else None
        ), {
            "verdict": "undetermined",
            "reason": "need_at_least_2_connections",
            "connections_seen": len(conns),
        }

    per_conn_order = [_ext_types(ch) for _, ch in conns]
    type_sets = [set(o) for o in per_conn_order]
    common = set.intersection(*type_sets) - ORDER_EXCLUDED_TYPES

    if len(common) < 2:
        return False, list(per_conn_order[0]), {
            "verdict": "undetermined",
            "reason": "insufficient_common_extensions",
            "common_extension_count": len(common),
        }

    # Project each connection's order onto the common subset.
    projections = [tuple(t for t in order if t in common) for order in per_conn_order]
    distinct = set(projections)
    permuted = len(distinct) >= 2

    detail = {
        "verdict": "permuted" if permuted else "stable",
        "compared_connections": len(conns),
        "common_extension_count": len(common),
        "distinct_orders_seen": len(distinct),
    }

    if permuted:
        detail["sample_orders"] = [
            [f"0x{t:04x}" for t in order] for order in list(distinct)[:3]
        ]
        return True, None, detail

    # Stable: expose the full (non-GREASE) order from the first connection.
    return False, list(per_conn_order[0]), detail

def _classify_extension_set_drift(
    type_sets: list[set],
) -> tuple[list[str], list[str]]:
    anomalies: list[str] = []
    informational: list[str] = []

    union = set().union(*type_sets)
    inter = set.intersection(*type_sets)
    varying = union - inter
    if not varying:
        return anomalies, informational

    expected = varying & VOLATILE_EXT_TYPES
    unexpected = varying - VOLATILE_EXT_TYPES

    if expected:
        informational.append(
            "extension_set_varies_expected:"
            + ",".join(f"0x{t:04x}" for t in sorted(expected))
        )
        # Call out resumption / ECH explicitly when we can.
        if PRE_SHARED_KEY in expected or EARLY_DATA in expected:
            informational.append("session_resumption_detected")
        if ENCRYPTED_CLIENT_HELLO in expected:
            informational.append("ech_presence_varies")

    if unexpected:
        anomalies.append(
            "extension_types_differ_unexpectedly:"
            + ",".join(f"0x{t:04x}" for t in sorted(unexpected))
        )

    return anomalies, informational


def analyze_variation(
    conns: list[tuple[str, ClientHello]]
) -> tuple[dict, bool, list[int] | None]:
    if not conns:
        return {"stable": [], "varied": {}, "anomalies": [], "informational": []}, False, None

    stable: list[str] = []
    varied: dict = {}
    anomalies: list[str] = []
    informational: list[str] = []

    type_sets = [set(_ext_types(ch)) for _, ch in conns]

    # --- Cipher multisets (should be identical) ---
    if len({_cipher_multiset(ch) for _, ch in conns}) == 1:
        stable.append("ciphers_multiset")
    else:
        anomalies.append("cipher_suites_differ_across_conns")

    # --- Extension type sets (may differ for benign reasons) ---
    if len({frozenset(s) for s in type_sets}) == 1:
        stable.append("extensions_set")
    else:
        set_anoms, set_info = _classify_extension_set_drift(type_sets)
        anomalies.extend(set_anoms)
        informational.extend(set_info)

    # --- Supported groups (should be stable) ---
    sg_lists = {tuple(filter_grease(_sg_list(ch))) for _, ch in conns}
    if len(sg_lists) == 1:
        stable.append("supported_groups")
    else:
        anomalies.append("supported_groups_differ_across_conns")

    # --- Signature algorithms (should be stable) ---
    if len({_sig_algs(ch) for _, ch in conns}) == 1:
        stable.append("signature_algorithms")
    else:
        anomalies.append("signature_algorithms_differ_across_conns")

    # --- ALPN: differences are expected when ECH presence varies
    #     (outer hello carries public ALPN, inner carries the real one) ---
    alpn_lists = {_alpn(ch) for _, ch in conns}
    ech_presence = {ENCRYPTED_CLIENT_HELLO in s for s in type_sets}
    if len(alpn_lists) == 1:
        stable.append("alpn")
    elif len(ech_presence) > 1 or ech_presence == {True}:
        informational.append("alpn_varies_likely_ech_outer_inner")
    else:
        anomalies.append("alpn_differs_across_conns")

    # --- Extension order permutation (robust to set drift) ---
    permute_extensions, canonical_ext_order, ext_order_detail = (
        _detect_extension_permutation(conns)
    )
    if ext_order_detail["verdict"] == "permuted":
        varied["extension_order"] = ext_order_detail
    elif ext_order_detail["verdict"] == "stable":
        stable.append("extension_order")
    else:
        # Couldn't decide (too few connections / too little overlap).
        informational.append(
            f"extension_order_undetermined:{ext_order_detail.get('reason')}"
        )

    # --- Key share group order ---
    ks_orders = {tuple(_ks_groups(ch)) for _, ch in conns}
    if len(ks_orders) >= 2:
        varied["key_share_group_order"] = {
            "verdict": "permuted",
            "distinct_orders_seen": len(ks_orders),
            # NOTE: with only 2-3 key-share groups, identical orders can recur
            # by chance, so a "stable" reading here is weaker than for extensions.
        }
    else:
        stable.append("key_share_group_order")

    # --- GREASE: presence (static) vs. rotation (across connections) ---
    grease_present = any(_has_grease(ch) for _, ch in conns)

    cipher_grease = [
        frozenset(v for v in ch.cipher_suites if is_grease_u16(v)) for _, ch in conns
    ]
    ext_grease = [
        frozenset(e.ext_type for e in ch.extensions if is_grease_u16(e.ext_type))
        for _, ch in conns
    ]
    distinct_cipher_grease = len(set(cipher_grease))
    distinct_ext_grease = len(set(ext_grease))
    grease_rotates = grease_present and (
        distinct_cipher_grease > 1 or distinct_ext_grease > 1
    )

    grease_report = {
        "present": grease_present,
        "rotates": grease_rotates,
        "cipher_distinct_grease_sets": distinct_cipher_grease,
        "ext_distinct_grease_sets": distinct_ext_grease,
    }
    if grease_present and not grease_rotates and len(conns) < 2:
        grease_report["rotation_undetermined"] = "need_at_least_2_connections"

    report = {
        "stable": stable,
        "varied": varied,
        "anomalies": anomalies,
        "informational": informational,
        "grease": grease_report,
        "connections_analyzed": len(conns),
    }

    return report, permute_extensions, canonical_ext_order