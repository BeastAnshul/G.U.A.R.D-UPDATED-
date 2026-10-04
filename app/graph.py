"""Directed host communication graph from observed flows."""
from __future__ import annotations

from collections import defaultdict

import networkx as nx
import pandas as pd

def build_graph(flows: pd.DataFrame, scored: list[dict]) -> dict:
    risk_by_pair = defaultdict(list)
    for item in scored:
        risk_by_pair[(item["source_ip"], item["destination_ip"])].append(item["anomaly_score"])
    graph = nx.DiGraph()
    for _, row in flows.iterrows():
        src, dst = str(row.src_ip), str(row.dst_ip)
        if src == "unknown" or dst == "unknown":
            continue
        if graph.has_edge(src, dst):
            edge = graph[src][dst]
            edge["flow_count"] += 1
            edge["bytes"] += _float(row.bytes)
            edge["packets"] += _float(row.packets)
            edge["protocols"].add(str(row.protocol))
        else:
            graph.add_edge(src, dst, flow_count=1, bytes=_float(row.bytes), packets=_float(row.packets), protocols={str(row.protocol)})
    for node in graph.nodes:
        incident = []
        for src, dst in graph.in_edges(node):
            incident.extend(risk_by_pair.get((src, dst), []))
        for src, dst in graph.out_edges(node):
            incident.extend(risk_by_pair.get((src, dst), []))
        graph.nodes[node]["risk"] = round(sum(incident) / len(incident), 1) if incident else 0.0
    all_nodes = sorted(graph.nodes, key=lambda n: (graph.degree(n), graph.nodes[n]["risk"]), reverse=True)
    keep = set(all_nodes[:80])
    nodes = [{"id": node, "in_degree": graph.in_degree(node), "out_degree": graph.out_degree(node), "risk": graph.nodes[node]["risk"]} for node in all_nodes if node in keep]
    edges = []
    for src, dst, data in graph.edges(data=True):
        if src not in keep or dst not in keep:
            continue
        pair_risk = risk_by_pair.get((src, dst), [])
        edges.append({"source": src, "target": dst, "flow_count": data["flow_count"], "bytes": round(data["bytes"], 1), "packets": round(data["packets"], 1), "protocols": sorted(data["protocols"]), "risk": round(sum(pair_risk) / len(pair_risk), 1) if pair_risk else 0.0})
    edges.sort(key=lambda e: (e["risk"], e["flow_count"], e["bytes"]), reverse=True)
    undirected = graph.to_undirected()
    return {"directed": True, "node_count": graph.number_of_nodes(), "edge_count": graph.number_of_edges(), "shown_nodes": len(nodes), "shown_edges": min(160, len(edges)), "truncated": graph.number_of_nodes() > 80 or len(edges) > 160, "density": round(nx.density(graph), 5) if graph.number_of_nodes() > 1 else 0.0, "connected_components": nx.number_connected_components(undirected), "nodes": nodes, "edges": edges[:160]}

def _float(value) -> float:
    try:
        return float(value) if pd.notna(value) else 0.0
    except (ValueError, TypeError):
        return 0.0
