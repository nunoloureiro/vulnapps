#!/usr/bin/env python3
"""Seed TaintedPort chain sinks (migration 045) on a vulnapps app.

Sets `sink_vuln_id` on every existing path, registers the two new paths, and
names each chain (migration 046),
from the catalog's CHAINS and ATTACK PATHS tables (TaintedPort-Vulns
KnownVulnerabilities.txt). Dry run unless --apply.

Catalog numbers (#N) are not stored on vulnapps, so they are resolved through
the live chains themselves: the seed lists each path's members in catalog
order, and the app's chain rows list them in the same order. Every catalog
number must resolve to the SAME vuln in every path it appears in (#40 in
CHAIN-001/008/009/010, #24 in 008/010/013/014, ...); any disagreement, a
missing chain, or a member-count mismatch aborts before anything is written.

    VULNAPPS_URL=... VULNAPPS_API_KEY=va_... python tools/seed_chain_sinks.py --app-id 329
    ... --apply
"""
from __future__ import annotations

import argparse
import os
import sys

try:
    # OS trust store (Keychain etc.) instead of certifi: the Zscaler proxy
    # re-signs HTTPS with a root only the OS trusts. Must precede httpx.
    # Same as tools/import_scan.py.
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

import httpx

# path -> (members in catalog order, sink)
PATHS = {
    "CHAIN-001": ([1, 40], 40), "CHAIN-008": ([17, 24, 40], 40),
    "CHAIN-009": ([49, 51, 40], 40), "CHAIN-010": ([53, 24, 40], 40),
    "CHAIN-002": ([11, 23], 23), "CHAIN-003": ([12, 23], 23),
    "CHAIN-006": ([13, 45], 45),
    "CHAIN-016": ([27, 60], 60),
    "CHAIN-005": ([44, 43], 43),  # execution order: read the log (#44), then the token (#43)
    "CHAIN-013": ([17, 24, 20], 20),
    "CHAIN-014": ([53, 24, 28], 28), "CHAIN-015": ([3, 28], 28),
    "CHAIN-012": ([56, 29], 29),
    "CHAIN-007": ([46, 47], 47),
}

NEW_PATHS = {
    "CHAIN-017": {
        "members": [20, 43], "sink": 43, "severity": "critical",
        "title": "2FA-Disable IDOR -> Predictable Reset Token Takeover",
        "description": "Strip the victim's 2FA via the disable IDOR (#20), then reset their "
                       "password with the predictable token (#43). No crack needed. First "
                       "demonstrated by a COS scan of 2026-10-31.",
    },
    "CHAIN-018": {
        "members": [17, 24, 28], "sink": 28, "severity": "high",
        "title": "BOLA Order Read -> Hash + TOTP Seed Leak -> 2FA Takeover",
        "description": "BOLA order read (#17) -> the response leaks password_hash and "
                       "totp_secret (#24) -> compute a valid TOTP from the leaked seed (#28); "
                       "the hash must still be cracked offline (High, as CHAIN-014/015). First "
                       "demonstrated by a COS scan of 2026-10-31.",
    },
}

# Chain ids (migration 047) in the catalog's CHAINS table order: chain code ->
# its attack paths (by their original CHAIN-### id), numbered .1, .2, ...
IDS = {
    "CH-01": ["CHAIN-001", "CHAIN-008", "CHAIN-009", "CHAIN-010"],
    "CH-02": ["CHAIN-002", "CHAIN-003"],
    "CH-03": ["CHAIN-006"],
    "CH-04": ["CHAIN-016"],
    "CH-05": ["CHAIN-005", "CHAIN-017"],
    "CH-06": ["CHAIN-013"],
    "CH-07": ["CHAIN-014", "CHAIN-015", "CHAIN-018"],
    "CH-08": ["CHAIN-012"],
    "CH-09": ["CHAIN-007"],
}

# Chain names, keyed by end step, from the catalog's CHAINS table.
NAMES = {
    40: "Pass-the-hash account takeover",
    23: "Admin claim forgery, signature not enforced",
    45: "Admin forgery via algorithm confusion",
    60: "Admin forgery via recovered signing secret",
    43: "Takeover via predictable reset token",
    20: "2FA-disable IDOR -> account takeover",
    28: "2FA-protected takeover via leaked TOTP seed",
    29: "CSRF-delivered XSS -> session token theft",
    47: "Deserialization gadget -> RCE",
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--app-id", type=int, required=True)
    ap.add_argument("--url", default=os.environ.get("VULNAPPS_URL"))
    ap.add_argument("--api-key", default=os.environ.get("VULNAPPS_API_KEY"))
    ap.add_argument("--apply", action="store_true", help="write the changes (default: dry run)")
    args = ap.parse_args()
    if not args.url or not args.api_key:
        sys.exit("Set --url/--api-key or VULNAPPS_URL/VULNAPPS_API_KEY")

    client = httpx.Client(base_url=args.url.rstrip("/"), timeout=30,
                          headers={"Authorization": f"Bearer {args.api_key}"})
    base = f"/api/apps/{args.app_id}/chains"
    resp = client.get(base)
    resp.raise_for_status()
    # Keyed by the path's original CHAIN-### id, which survives renumbering.
    live = {(c.get("legacy_chain_id") or c["chain_id"]): c for c in resp.json()["chains"]}

    # Resolve catalog numbers through the existing paths, cross-checking each.
    catalog: dict[int, dict] = {}
    errors = []
    for chain_id, (members, _sink) in PATHS.items():
        chain = live.get(chain_id)
        if chain is None:
            errors.append(f"{chain_id} is not registered on app {args.app_id}")
            continue
        if len(chain["members"]) != len(members):
            errors.append(f"{chain_id} has {len(chain['members'])} members, catalog says {len(members)}")
            continue
        for number, m in zip(members, chain["members"]):
            seen = catalog.setdefault(number, m)
            if seen["vuln_id"] != m["vuln_id"]:
                errors.append(f"#{number} is {seen['vuln_code']} in one path but "
                              f"{m['vuln_code']} in {chain_id}")
    if errors:
        print("Aborting, nothing written:\n  " + "\n  ".join(errors))
        return 1

    label = lambda n: f"#{n}={catalog[n]['vuln_code']}"
    for chain_id, (members, sink) in PATHS.items():
        chain = live[chain_id]
        sink_vuln = catalog[sink]["vuln_id"]
        state = "ok" if chain.get("sink_vuln_id") == sink_vuln else "set"
        print(f"{state:4} {chain_id} sink {label(sink)}  ({' + '.join(label(n) for n in members)})")
        if state == "set" and args.apply:
            client.put(f"{base}/{chain['id']}", json={"sink_vuln_id": sink_vuln}).raise_for_status()

    for chain_id, spec in NEW_PATHS.items():
        desc = f"{chain_id} sink {label(spec['sink'])}  ({' + '.join(label(n) for n in spec['members'])})"
        if chain_id in live:
            print(f"ok   {desc} (already registered)")
            continue
        print(f"new  {desc} {spec['severity']}")
        if args.apply:
            client.post(base, json={
                "chain_id": chain_id, "title": spec["title"], "severity": spec["severity"],
                "description": spec["description"],
                "member_vuln_ids": [catalog[n]["vuln_id"] for n in spec["members"]],
                "sink_vuln_id": catalog[spec["sink"]]["vuln_id"],
            }).raise_for_status()

    # Names are shared by every path to a sink: writing one path names the chain.
    for sink, name in NAMES.items():
        path = next(c for cid, c in live.items() if cid in PATHS and PATHS[cid][1] == sink)
        state = "ok" if path.get("chain_name") == name else "name"
        print(f"{state:4} chain ending on {label(sink)}: {name}")
        if state == "name" and args.apply:
            client.put(f"{base}/{path['id']}", json={"chain_name": name}).raise_for_status()

    # Renumber into CH-NN / CH-NN.n. Chain codes go through temporary ones first
    # (CH-9N), since the codes a migration assigned may already hold the targets.
    if args.apply:
        live = {(c.get("legacy_chain_id") or c["chain_id"]): c
                for c in client.get(base).json()["chains"]}
    wanted = {old: (code, f"{code}.{i}") for code, olds in IDS.items()
              for i, old in enumerate(olds, start=1)}
    todo = {old: w for old, w in wanted.items()
            if old in live and (live[old].get("chain_code"), live[old]["chain_id"]) != w}
    for old, (code, path_id) in wanted.items():
        state = "ok" if old not in todo else "id"
        print(f"{state:4} {old} -> {path_id}")
    if todo and args.apply:
        for n, (code, olds) in enumerate(IDS.items(), start=1):
            client.put(f"{base}/{live[olds[0]]['id']}", json={"chain_code": f"CH-{90 + n}"}).raise_for_status()
        for old, (code, path_id) in wanted.items():
            client.put(f"{base}/{live[old]['id']}", json={"chain_code": code, "chain_id": path_id}).raise_for_status()

    extra = sorted(set(live) - set(PATHS) - set(NEW_PATHS))
    if extra:
        print(f"note: app also has {', '.join(extra)}, not in the catalog table (left untouched)")
    print("applied" if args.apply else "dry run: re-run with --apply to write")
    return 0


if __name__ == "__main__":
    sys.exit(main())
