"""
Network Activity Graph Analyzer - Micro Project 09 (Digital Forensics, CO4)

Usage:
    python3 analyzer.py sample_logs.csv WS-01 203.0.113.25
    python3 analyzer.py sample_logs.csv WS-01 203.0.113.25 --threshold 20
    python3 analyzer.py sample_logs.csv WS-01 203.0.113.25 --time-order

Pipeline: log input -> graph construction -> suspicion scoring -> traversal -> report
Only the Python standard library is used (no pip install needed).

Assumptions (stated in the report):
  - Any host that is not an IP address (e.g. "WS-01") is treated as internal.
    A name like "EVIL-BOX" would also be treated as internal.
  - Hosts whose name starts with "WS-" are workstations.
  - The whole log file is loaded into memory once, so the hash and the
    analysis use exactly the same bytes. Very large logs need more RAM.
"""

import argparse
import csv
import hashlib
import io
import ipaddress
from collections import deque
from datetime import datetime


# ---------------------------------------------------------------------------
# Settings (all rule values in one place so they are easy to tune and explain)
# ---------------------------------------------------------------------------

# Addresses inside the organisation. Host names like "WS-01" are also internal.
INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
ALLOW_LIST = {"8.8.8.8"}          # known-good external hosts, never flagged

ADMIN_PORTS = {445, 3389}         # SMB and Remote Desktop
LARGE_BYTES = 500_000_000         # more than 500 MB in one connection
SMALL_BYTES = 10_000              # a "small" connection carries under 10 KB
REPEAT_COUNT = 30                 # 30+ small connections to one host

MAX_HOPS = 8                      # DFS path length cap
MAX_PATHS = 20                    # DFS stops after finding this many paths

TIME_FORMAT = "%Y-%m-%d %H:%M"


# ---------------------------------------------------------------------------
# Stage 1: log input + evidence hash
# ---------------------------------------------------------------------------

def load_evidence(path):
    """
    Read the file ONCE. The same bytes are hashed and then parsed, so the
    hash always describes exactly the data that was analysed.
    """
    with open(path, "rb") as f:
        data = f.read()
    evidence_hash = hashlib.sha256(data).hexdigest()
    return data, evidence_hash


def parse_row(row):
    """Convert one CSV row to a typed record. Raises ValueError with a clear reason."""
    values = {}
    for field in ("time", "src", "dst", "protocol", "port", "bytes"):
        value = row.get(field)
        if value is None or value.strip() == "":
            raise ValueError(f"missing {field}")
        values[field] = value.strip()

    try:
        time = datetime.strptime(values["time"], TIME_FORMAT)
    except ValueError:
        raise ValueError(f"invalid time {values['time']!r}")
    try:
        port = int(values["port"])
    except ValueError:
        raise ValueError(f"invalid port {values['port']!r}")
    try:
        size = int(values["bytes"])
    except ValueError:
        raise ValueError(f"invalid bytes {values['bytes']!r}")

    return {
        "time": time,
        "src": values["src"],
        "dst": values["dst"],
        "protocol": values["protocol"],
        "port": port,
        "bytes": size,
    }


def parse_logs(data):
    """
    Parse the CSV bytes. Bad rows are not dropped silently and do not crash
    the program: they are collected with their line number for the report.
    """
    text = data.decode("utf-8-sig")             # utf-8-sig also removes an Excel BOM
    records = []
    skipped = []                                # [(line_no, reason), ...]
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        try:
            records.append(parse_row(row))
        except ValueError as e:
            skipped.append((reader.line_num, str(e)))   # real file line, blank lines counted
    return records, skipped


# ---------------------------------------------------------------------------
# Stage 2: graph construction (directed graph, adjacency list)
# ---------------------------------------------------------------------------

def build_graph(records):
    """
    adj   : {node: [neighbour, ...]}         -> used by BFS / DFS
    edges : {(src, dst): [record, record...]} -> repeated connections merged
                                                 into one edge, records kept
                                                 so count/bytes/time rules work
    """
    adj = {}
    edges = {}
    for r in records:
        src, dst = r["src"], r["dst"]
        adj.setdefault(src, [])
        adj.setdefault(dst, [])          # dst becomes a node even with no out-edges
        if (src, dst) not in edges:
            edges[(src, dst)] = []
            adj[src].append(dst)         # add the edge only once
        edges[(src, dst)].append(r)
    return adj, edges


# ---------------------------------------------------------------------------
# Stage 3: suspicion scoring (explainable rules)
# ---------------------------------------------------------------------------

def is_internal(host):
    """
    IPs are checked against our ranges. ASSUMPTION: any non-IP name is
    internal (a real deployment would check names against an asset list).
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True
    return any(ip in net for net in INTERNAL_NETWORKS)


def is_workstation(host):
    return host.startswith("WS-")


def score_edge(src, dst, recs):
    """Return (points, [reasons]) for one merged edge."""
    points = 0
    reasons = []

    if not is_internal(dst) and dst not in ALLOW_LIST:
        points += 30
        reasons.append("unknown external")

    if any(0 <= r["time"].hour <= 5 for r in recs):          # 00:00-05:59
        points += 15
        reasons.append("off-hours")

    if any(r["bytes"] > LARGE_BYTES for r in recs):
        points += 25
        reasons.append("large transfer")

    if (is_workstation(src) and is_workstation(dst)
            and any(r["port"] in ADMIN_PORTS for r in recs)):
        points += 20
        reasons.append("workstation admin port")

    if len(recs) >= REPEAT_COUNT and all(r["bytes"] < SMALL_BYTES for r in recs):
        points += 15
        reasons.append("repeated small connections")

    return points, reasons


def severity(points):
    if points >= 60:
        return "Critical"
    if points >= 30:
        return "High"
    if points >= 15:
        return "Medium"
    return "Low"


def score_all(edges):
    """{(src, dst): (points, reasons)} for every edge."""
    return {(s, d): score_edge(s, d, recs) for (s, d), recs in edges.items()}


def filter_graph(adj, scores, threshold):
    """Keep only edges whose score >= threshold (threshold 0 keeps everything)."""
    return {u: [v for v in nbrs if scores[(u, v)][0] >= threshold]
            for u, nbrs in adj.items()}


# ---------------------------------------------------------------------------
# Stage 4: traversal
# ---------------------------------------------------------------------------

def bfs(adj, start):
    depth = {start: 0}
    parent = {start: None}
    queue = deque([start])
    while queue:
        u = queue.popleft()
        for v in adj.get(u, []):
            if v not in depth:
                depth[v] = depth[u] + 1
                parent[v] = u
                queue.append(v)
    return depth, parent


def shortest_path(parent, target):
    """Walk the parent map back from target to start, then reverse."""
    if target not in parent:
        return None
    path = []
    node = target
    while node is not None:
        path.append(node)
        node = parent[node]
    return path[::-1]


def all_paths(adj, edges, u, target, time_order=False,
              path=None, seen=None, after=None, found=None):
    """
    DFS with backtracking: list simple paths from u to target.

    found      : ONE shared list for the whole search, so we can stop as soon
                 as MAX_PATHS paths exist (not generate all, then cut).
    time_order : if True, each next connection must happen at or after the
                 previous one (a train route: you can't catch the 8:00 train
                 after arriving on the 9:00 train).
    after      : time we arrived at u (None at the start host).
    """
    if found is None:
        found = []
    path = (path or []) + [u]
    seen = (seen or set()) | {u}

    if u == target:
        found.append(path)
        return found
    if len(path) > MAX_HOPS:             # cap: path count grows exponentially
        return found

    for v in adj.get(u, []):
        if len(found) >= MAX_PATHS:      # early stop
            break
        if v in seen:
            continue
        if time_order:
            times = [r["time"] for r in edges[(u, v)]
                     if after is None or r["time"] >= after]
            if not times:
                continue                 # no connection late enough -> not causal
            # take the EARLIEST valid connection: it leaves the most room
            # for later hops, so we never miss a valid chain
            all_paths(adj, edges, v, target, True, path, seen, min(times), found)
        else:
            all_paths(adj, edges, v, target, False, path, seen, None, found)
    return found


def path_score(path, scores):
    """Total suspicion = sum of the edge scores along the path."""
    return sum(scores[(path[i], path[i + 1])][0] for i in range(len(path) - 1))


# ---------------------------------------------------------------------------
# Stage 5: reporting
# ---------------------------------------------------------------------------

def all_hosts(scores):
    """Every host that appears in any edge."""
    hosts = set()
    for u, v in scores:
        hosts.add(u)
        hosts.add(v)
    return hosts


def print_report(evidence_hash, records, skipped, start, target,
                 depth, parent, paths, scores, time_order):
    print(f"Evidence SHA-256 : {evidence_hash}")
    print(f"Records parsed   : {len(records)}")
    if skipped:
        details = "; ".join(f"line {n}: {why}" for n, why in skipped)
        print(f"Skipped rows     : {len(skipped)} ({details})")
    else:
        print("Skipped rows     : 0")
    print(f"Start host       : {start}    Algorithm: BFS + DFS")
    print(f"DFS mode         : {'time-ordered (causal)' if time_order else 'any order'}")
    print()

    # Group BFS result by hop distance (skip depth 0 = start itself)
    levels = {}
    for host, d in depth.items():
        if d > 0:
            levels.setdefault(d, []).append(host)
    for d in sorted(levels):
        print(f"Depth {d} : {', '.join(levels[d])}")
    print(f"Total reached : {len(depth) - 1} hosts")
    print()

    if target:
        sp = shortest_path(parent, target)
        if sp:
            print(f"Shortest path : {' -> '.join(sp)} ({len(sp) - 1} hops)")
        else:
            print(f"Shortest path : {target} is not reachable from {start}")
        print()

        ranked = sorted(paths, key=lambda p: path_score(p, scores), reverse=True)
        print(f"DFS paths {start} -> {target}, ranked by score")
        if not ranked:
            print("  (none)")
        for i, p in enumerate(ranked, 1):
            print(f"  {i}. {' -> '.join(p)}   score {path_score(p, scores)}")
        if len(paths) >= MAX_PATHS:
            print(f"  (stopped at {MAX_PATHS} paths; more may exist)")
        print()

    # Flagged edges: only edges leaving a reached host (in scope) with points > 0
    print("Flagged edges")
    flagged = [(e, s) for e, s in scores.items() if s[0] > 0 and e[0] in depth]
    flagged.sort(key=lambda x: x[1][0], reverse=True)
    if not flagged:
        print("  (none)")
    for (u, v), (pts, reasons) in flagged:
        print(f"  {u} -> {v}  {pts:>3}  {severity(pts):<8}  {', '.join(reasons)}")
    print()

    out_of_scope = sorted(h for h in all_hosts(scores) if h not in depth)
    if out_of_scope:
        print(f"Not reachable from {start} (out of scope): {', '.join(out_of_scope)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Network Activity Graph Analyzer")
    ap.add_argument("log", help="CSV file: time,src,dst,protocol,port,bytes")
    ap.add_argument("start", help="first host flagged by the alert")
    ap.add_argument("target", nargs="?", help="host to trace paths to (optional)")
    ap.add_argument("--threshold", type=int, default=0,
                    help="follow only edges with score >= this value")
    ap.add_argument("--time-order", action="store_true",
                    help="DFS follows only connections that happen after the previous one")
    args = ap.parse_args()

    data, evidence_hash = load_evidence(args.log)     # 1. read once + hash
    records, skipped = parse_logs(data)               # 1. parse same bytes
    adj, edges = build_graph(records)                 # 2. graph
    scores = score_all(edges)                         # 3. scoring
    adj = filter_graph(adj, scores, args.threshold)   # 3. optional filter

    if args.start not in adj:
        print(f"Start host {args.start} not found in log.")
        if skipped:
            print(f"Note: {len(skipped)} row(s) were skipped as malformed; check the log.")
        return
    if args.target and args.target not in adj:
        print(f"Target host {args.target} not found in log.")
        return

    depth, parent = bfs(adj, args.start)              # 4. BFS
    paths = (all_paths(adj, edges, args.start, args.target, args.time_order)
             if args.target else [])                  # 4. DFS

    print_report(evidence_hash, records, skipped, args.start, args.target,
                 depth, parent, paths, scores, args.time_order)   # 5. report


if __name__ == "__main__":
    main()
