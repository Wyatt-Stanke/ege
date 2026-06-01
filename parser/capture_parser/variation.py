"""Per-session variation analysis.

Walks all conn_NNNN parsed ClientHellos in a session, detects:
- Extension order permutation (Chrome ≥ 110)
- Key share group order permutation
- GREASE value rotation
- Anomalies (unexpected config drift)
"""
from collections import Counter, defaultdict

from .tls.records import ClientHello
from .tls.grease import filter_grease, is_grease_u16


def _ext_type_list(ch: ClientHello, filter_g: bool = True) -> list[int]:
    types = [e.ext_type for e in ch.extensions]
    return filter_grease(types) if filter_g else types


def _sg_list(ch: ClientHello) -> list[int]:
    for e in ch.extensions:
        if e.ext_type == 0x000A:
            return e.parsed.get("groups", [])
    return []


def _ks_groups(ch: ClientHello) -> list[int]:
    for e in ch.extensions:
        if e.ext_type == 0x0033:
            return filter_grease([entry["group"] for entry in e.parsed.get("entries", [])])
    return []


def _cipher_multiset(ch: ClientHello) -> frozenset:
    return frozenset(Counter(filter_grease(ch.cipher_suites)).items())


def _ext_multiset(ch: ClientHello) -> frozenset:
    return frozenset(Counter(_ext_type_list(ch, filter_g=True)).items())


def analyze_variation(
    conns: list[tuple[str, ClientHello]]  # [(conn_id, ch), …]
) -> tuple[dict, bool, list[int] | None]:
    """
    Returns (variation_report, permute_extensions, canonical_ext_order).

    canonical_ext_order: non-GREASE extension types from the first conn,
                         or None when permute_extensions is True.
    """
    if not conns:
        return {}, False, None

    stable = []
    varied = {}
    anomalies = []

    # --- Cipher multisets: should all be identical ---
    cipher_sets = [_cipher_multiset(ch) for _, ch in conns]
    if len(set(cipher_sets)) == 1:
        stable.append("ciphers_multiset")
    else:
        anomalies.append("cipher_suites_differ_across_conns")

    # --- Extension multisets: should be identical (order may differ) ---
    ext_sets = [_ext_multiset(ch) for _, ch in conns]
    if len(set(ext_sets)) == 1:
        stable.append("extensions_multiset")
    else:
        anomalies.append("extension_types_differ_across_conns")

    # --- Supported groups (should be stable) ---
    sg_lists = [tuple(filter_grease(_sg_list(ch))) for _, ch in conns]
    if len(set(sg_lists)) == 1:
        stable.append("supported_groups")
    else:
        anomalies.append("supported_groups_differ_across_conns")

    # --- Signature algorithms (should be stable) ---
    sa_lists = []
    for _, ch in conns:
        for e in ch.extensions:
            if e.ext_type == 0x000D:
                sa_lists.append(tuple(e.parsed.get("algorithms", [])))
                break
        else:
            sa_lists.append(())
    if len(set(sa_lists)) == 1:
        stable.append("signature_algorithms")
    else:
        anomalies.append("signature_algorithms_differ_across_conns")

    # --- ALPN (should be stable) ---
    alpn_lists = []
    for _, ch in conns:
        for e in ch.extensions:
            if e.ext_type == 0x0010:
                alpn_lists.append(tuple(e.parsed.get("protocols", [])))
                break
        else:
            alpn_lists.append(())
    if len(set(alpn_lists)) == 1:
        stable.append("alpn")
    else:
        anomalies.append("alpn_differs_across_conns")

    # --- Extension order permutation detection ---
    ext_orders = [tuple(_ext_type_list(ch, filter_g=True)) for _, ch in conns]
    canonical_ext_order = list(ext_orders[0]) if ext_orders else None

    multiset_groups: dict = defaultdict(list)
    for ms, order in zip(ext_sets, ext_orders):
        multiset_groups[ms].append(order)

    permute_extensions = False
    for ms, orders in multiset_groups.items():
        if len(orders) >= 2 and len(set(orders)) >= 2:
            permute_extensions = True
            distinct_orders = len(set(orders))
            varied["extension_order"] = {
                "verdict": "permuted",
                "distinct_orders_seen": distinct_orders,
                "permuted_extensions_subset": [
                    f"0x{v:04x}" for v in orders[0]
                ],
            }
            canonical_ext_order = None
            break

    # --- Key share group order ---
    ks_orders = [tuple(_ks_groups(ch)) for _, ch in conns]
    distinct_ks = len(set(ks_orders))
    if distinct_ks >= 2:
        varied["key_share_group_order"] = {
            "verdict": "permuted",
            "distinct_orders_seen": distinct_ks,
        }

    # --- GREASE value rotation ---
    def grease_vals_for(ch: ClientHello, attr_fn) -> frozenset:
        return frozenset(v for v in attr_fn(ch) if is_grease_u16(v))

    cipher_grease_vals = [grease_vals_for(ch, lambda c: c.cipher_suites) for _, ch in conns]
    ext_grease_vals = [
        grease_vals_for(ch, lambda c: [e.ext_type for e in c.extensions])
        for _, ch in conns
    ]
    distinct_cipher_grease = len(set(frozenset(s) for s in cipher_grease_vals))
    distinct_ext_grease = len(set(frozenset(s) for s in ext_grease_vals))

    if distinct_cipher_grease > 1 or distinct_ext_grease > 1:
        varied["grease_values"] = {
            "verdict": "rotating_as_expected",
            "ciphers_grease_distinct_values": distinct_cipher_grease,
            "extensions_grease_distinct_values": distinct_ext_grease,
        }

    report = {
        "stable": stable,
        "varied": varied,
        "anomalies": anomalies,
    }

    return report, permute_extensions, canonical_ext_order
