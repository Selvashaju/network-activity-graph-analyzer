"""
Network Activity Graph Analyzer - web interface (Streamlit)
Run:  streamlit run app.py
Uses the functions in analyzer.py, so the CLI and the website give the same results.
"""

import hashlib

import streamlit as st

import analyzer as az

SEV_COLOR = {"Critical": "#c0392b", "High": "#e67e22", "Medium": "#d4ac0d", "Low": "#95a5a6"}


def q(name):
    """Quote a host name for Graphviz DOT."""
    return '"' + name.replace('"', '\\"') + '"'


st.set_page_config(page_title="Network Activity Graph Analyzer", layout="wide")
st.title("Network Activity Graph Analyzer")
st.caption("Micro Project 09 · Digital Forensics · CO4 · BFS / DFS on simulated flow logs")

uploaded = st.file_uploader("Upload a flow log (CSV: time,src,dst,protocol,port,bytes)", type="csv")
if uploaded is None:
    st.info("Upload sample_logs.csv or test_logs.csv to start.")
    st.stop()

# Stage 1: same bytes are hashed and parsed
data = uploaded.getvalue()
evidence_hash = hashlib.sha256(data).hexdigest()
records, skipped = az.parse_logs(data)
if not records:
    st.error("No valid rows found in this file.")
    st.stop()

# Stages 2-3: graph + scoring
adj_full, edges = az.build_graph(records)
scores = az.score_all(edges)
hosts = sorted(adj_full)

# Controls
c1, c2, c3, c4 = st.columns(4)
start = c1.selectbox("Start host", hosts, index=hosts.index("WS-01") if "WS-01" in hosts else 0)
target_choice = c2.selectbox("Target host", ["(none)"] + [h for h in hosts if h != start])
threshold = c3.slider("Follow edges with score ≥", 0, 100, 0, 5)
time_order = c4.checkbox("Time-ordered paths only")
target = None if target_choice == "(none)" else target_choice

# Stage 4: traversal
adj = az.filter_graph(adj_full, scores, threshold)
depth, parent = az.bfs(adj, start)
paths = az.all_paths(adj, edges, start, target, time_order) if target else []
ranked = sorted(paths, key=lambda p: az.path_score(p, scores), reverse=True)
flagged = sorted(((e, s) for e, s in scores.items() if s[0] > 0 and e[0] in depth),
                 key=lambda x: x[1][0], reverse=True)

# Summary
m1, m2, m3, m4 = st.columns(4)
m1.metric("Records parsed", len(records))
m2.metric("Skipped rows", len(skipped))
m3.metric("Hosts reached", len(depth) - 1)
m4.metric("Flagged edges", len(flagged))

st.markdown("**Evidence SHA-256**")
st.code(evidence_hash, language=None)
if skipped:
    st.warning("Skipped rows: " + "; ".join(f"line {n}: {why}" for n, why in skipped))

# Graph
best = ranked[0] if ranked else None
best_edges = set(zip(best, best[1:])) if best else set()
dot = ["digraph G {", "rankdir=LR;",
       'node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=11];',
       'edge [fontname="Helvetica", fontsize=10];']
for h in hosts:
    fill = "#1abc9c" if h == start else ("#d1f2eb" if h in depth else "#eeeeee")
    border = ", penwidth=2.5" if h == target else ""
    dot.append(f'{q(h)} [fillcolor="{fill}"{border}];')
for (u, v), (pts, _) in scores.items():
    width = 3.5 if (u, v) in best_edges else 1.2
    style = "solid" if pts >= threshold else "dashed"
    dot.append(f'{q(u)} -> {q(v)} [label="{pts}", color="{SEV_COLOR[az.severity(pts)]}", '
               f'penwidth={width}, style={style}];')
dot.append("}")

st.subheader("Network graph")
st.caption("Green = start host · light green = reached by BFS · grey = out of scope · "
           "edge label = suspicion score · bold = highest-scoring path · dashed = below threshold")
st.graphviz_chart("\n".join(dot), width="stretch")

# BFS + DFS results
left, right = st.columns(2)
with left:
    st.subheader("BFS scope")
    levels = {}
    for h, d in depth.items():
        if d > 0:
            levels.setdefault(d, []).append(h)
    st.dataframe([{"Depth (hops)": d, "Hosts": ", ".join(levels[d])} for d in sorted(levels)],
                 hide_index=True, width="stretch")
    if target:
        sp = az.shortest_path(parent, target)
        if sp:
            st.success(f"Shortest path: {' → '.join(sp)} ({len(sp) - 1} hops)")
        else:
            st.error(f"{target} is not reachable from {start}")

with right:
    st.subheader("DFS paths" + (" (time-ordered)" if time_order else ""))
    if not target:
        st.info("Pick a target host to list paths.")
    elif not ranked:
        st.info("No path found with the current settings.")
    else:
        st.dataframe([{"Rank": i, "Path": " → ".join(p), "Hops": len(p) - 1,
                       "Score": az.path_score(p, scores)} for i, p in enumerate(ranked, 1)],
                     hide_index=True, width="stretch")
        if len(paths) >= az.MAX_PATHS:
            st.caption(f"Stopped at {az.MAX_PATHS} paths; more may exist.")

st.subheader("Flagged edges (in scope)")
st.dataframe([{"Source": u, "Destination": v, "Score": pts, "Severity": az.severity(pts),
               "Data (MB)": round(sum(r["bytes"] for r in edges[(u, v)]) / 1_000_000, 1),
               "Reasons": ", ".join(why)} for (u, v), (pts, why) in flagged],
             hide_index=True, width="stretch")

out_of_scope = sorted(h for h in az.all_hosts(scores) if h not in depth)
if out_of_scope:
    st.caption(f"Not reachable from {start} (out of scope): {', '.join(out_of_scope)}")
