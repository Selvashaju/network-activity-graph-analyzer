# Network Activity Graph Analyzer

Micro Project 09 · Digital Forensics · CO4 · Karunya University

Turns network flow logs into a directed graph and uses **BFS** and **DFS** to trace how suspicious activity spreads from a compromised host during an investigation.

- **BFS** answers: *which hosts are within 1, 2, 3 hops of the first alert?* (scope of the incident, shortest path)
- **DFS** answers: *what full chain of connections links host A to host B?* (paths ranked by suspicion score)
- **Time-ordered DFS** keeps only causal chains, where each connection happens after the previous one.
- **SHA-256** hash of the log proves the evidence was not changed. The file is read once, so the hash covers exactly the bytes analysed.

Only the Python standard library is used. No `pip install` needed.

## How it works

1. **Log input** – read the CSV once, hash it, parse rows. Malformed rows are skipped and reported with their line number, never dropped silently.
2. **Graph construction** – devices become nodes, connections become edges in an adjacency list. Repeated connections between the same pair merge into one edge.
3. **Suspicion scoring** – explainable rules add points to each edge.
4. **Traversal** – BFS from the start host; DFS with backtracking to the target.
5. **Report** – reached hosts by depth, shortest path, ranked paths, flagged edges, out-of-scope hosts.

### Scoring rules

| Rule | Condition | Points |
| --- | --- | --- |
| Unknown external host | Destination outside internal ranges and not on the allow list | 30 |
| Off-hours activity | Connection between 00:00 and 05:59 | 15 |
| Large transfer | More than 500 MB in one connection | 25 |
| Workstation admin port | Port 445 or 3389 between two `WS-` hosts | 20 |
| Repeated small connections | 30+ connections, each under 10 KB | 15 |

Severity: 0–14 Low · 15–29 Medium · 30–59 High · 60+ Critical

## Usage

```bash
# 1. Normal run: BFS scope + all DFS paths to the target
python3 analyzer.py sample_logs.csv WS-01 203.0.113.25

# 2. Follow only suspicious edges (score >= 20)
python3 analyzer.py sample_logs.csv WS-01 203.0.113.25 --threshold 20

# 3. Causal paths only (each hop must happen after the previous one)
python3 analyzer.py test_logs.csv WS-01 203.0.113.25 --time-order
```

The target argument is optional. Without it, the report shows BFS scope and flagged edges only.

### Log format

```csv
time,src,dst,protocol,port,bytes
2026-10-20 09:10,WS-01,WS-04,SMB,445,12000000
```

Time format is `YYYY-MM-DD HH:MM`. All logs in this repo are simulated; external addresses come from the `203.0.113.0/24` documentation range.

## Sample output (`sample_logs.csv`)

```
Records parsed   : 5
Skipped rows     : 0
Start host       : WS-01    Algorithm: BFS + DFS
DFS mode         : any order

Depth 1 : WS-04, SRV-FILE
Depth 2 : SRV-DB
Depth 3 : 203.0.113.25
Total reached : 4 hosts

Shortest path : WS-01 -> WS-04 -> SRV-DB -> 203.0.113.25 (3 hops)

DFS paths WS-01 -> 203.0.113.25, ranked by score
  1. WS-01 -> WS-04 -> SRV-DB -> 203.0.113.25   score 115

Flagged edges
  SRV-DB -> 203.0.113.25   70  Critical  unknown external, off-hours, large transfer
  WS-04 -> SRV-DB   25  Medium    large transfer
  WS-01 -> WS-04   20  Medium    workstation admin port

Not reachable from WS-01 (out of scope): WS-02
```

## Time-order test (`test_logs.csv`)

`test_logs.csv` adds a second route through WS-05 and one malformed row.

| Connection | Time |
| --- | --- |
| WS-01 → WS-05 | 2026-10-20 15:00 |
| WS-05 → SRV-DB | 2026-10-20 07:00 |

WS-05 talked to SRV-DB *before* WS-01 ever reached WS-05, so activity from WS-01 cannot have travelled that way.

- Without `--time-order`, DFS lists two paths: via WS-04 (score 115) and via WS-05 (score 90).
- With `--time-order`, only the WS-04 path remains.
- The row with port `abc` is reported as skipped with its line number.

When several connections exist on one edge, the search follows the earliest valid one. Arriving earlier leaves the most options for the next hop, so no valid chain is missed.

## Complexity

| | Time | Space |
| --- | --- | --- |
| Graph build | O(E) | O(V + E) |
| BFS | O(V + E) | O(V) |
| DFS (one traversal) | O(V + E) | O(V) |

Listing all simple paths can grow exponentially, so DFS is capped at 8 hops and stops after 20 paths.

## Assumptions

- Any host that is not an IP address (for example `WS-01`) is treated as internal. A real deployment would check names against an asset inventory.
- Hosts whose name starts with `WS-` are workstations.
- The whole log is loaded into memory once, so very large logs need more RAM.

## Author

Shajilin Benadict S · B.Sc. Information Security and Digital Forensics · [github.com/Selvashaju](https://github.com/Selvashaju)
