"""Flow CSV normalization and network-state feature extraction."""
from __future__ import annotations

import ipaddress
import math
import re
from typing import Any

import numpy as np
import pandas as pd

ALIASES = {
    "src_ip": ["source ip", "src ip", "source", "srcip", "src address", "source address"],
    "dst_ip": ["destination ip", "dst ip", "destination", "dstip", "dst address", "destination address"],
    "src_port": ["source port", "src port", "sourceport", "srcport"],
    "dst_port": ["destination port", "dst port", "destinationport", "dstport"],
    "protocol": ["protocol", "proto"],
    "duration": ["flow duration", "duration", "duration ms", "flow duration us"],
    "packets": ["total packets", "packets", "total fwd packets", "tot fwd pkts", "packet count"],
    "bytes": ["total bytes", "bytes", "total length of fwd packets", "totlen fwd pkts", "byte count"],
    "syn": ["syn flag count", "syn count", "syn"],
    "ack": ["ack flag count", "ack count", "ack"],
    "timestamp": ["timestamp", "flow start", "start time", "time"],
    "label": ["label", "class", "attack"],
}

FEATURES = [
    ("flow_count", "flows", 2000, "Number of flow records in the upload."),
    ("unique_source_hosts", "hosts", 256, "Distinct source IP addresses."),
    ("unique_destination_hosts", "hosts", 256, "Distinct destination IP addresses."),
    ("unique_destination_ports", "ports", 128, "Distinct destination ports."),
    ("protocol_diversity", "protocols", 16, "Distinct observed protocol labels."),
    ("mean_flow_duration_ms", "ms", 60000, "Mean duration; microseconds converted to milliseconds when the header says us."),
    ("median_flow_duration_ms", "ms", 60000, "Median duration; microseconds converted to milliseconds when the header says us."),
    ("mean_packets_per_flow", "packets/flow", 1000, "Mean packet count per flow."),
    ("mean_bytes_per_flow", "bytes/flow", 1000000, "Mean byte count per flow."),
    ("total_bytes", "bytes", 1000000000, "Sum of byte counts."),
    ("syn_to_ack_ratio", "ratio", 10, "Total SYN flags divided by ACK flags plus one."),
    ("syn_flow_ratio", "ratio", 1, "Fraction of flows with at least one SYN flag."),
    ("external_destination_ratio", "ratio", 1, "Fraction of flows whose destination is not a private, loopback, or link-local IP."),
    ("flows_per_source_p95", "flows/host", 500, "95th percentile flow count per source host."),
    ("total_bytes_per_second", "bytes/s", 10000000, "Aggregate bytes divided by observed time span, when timestamps exist."),
    ("mean_packets_per_second", "packets/s", 10000, "Mean packet rate, when supplied or derivable."),
    ("destination_port_entropy", "bits", 8, "Shannon entropy of destination-port distribution."),
    ("unique_host_pairs", "pairs", 1000, "Distinct directed source-destination pairs."),
]

def _norm_header(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value).strip().lower()).strip()

def normalize_columns(frame: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, str]]:
    lookup = {_norm_header(col): col for col in frame.columns}
    out = pd.DataFrame(index=frame.index)
    sources: dict[str, str] = {}
    for target, aliases in ALIASES.items():
        original = next((lookup[_norm_header(alias)] for alias in aliases if _norm_header(alias) in lookup), None)
        if original is not None:
            out[target] = frame[original]
            sources[target] = str(original)
    for key in ("src_ip", "dst_ip"):
        if key not in out:
            out[key] = "unknown"
    for key in ("src_port", "dst_port", "duration", "packets", "bytes", "syn", "ack"):
        if key in out:
            out[key] = pd.to_numeric(out[key], errors="coerce").fillna(0)
        else:
            out[key] = np.nan
    out["src_ip"] = out["src_ip"].fillna("unknown").astype(str).str.strip()
    out["dst_ip"] = out["dst_ip"].fillna("unknown").astype(str).str.strip()
    if "protocol" in out:
        out["protocol"] = out["protocol"].fillna("unknown").astype(str).str.upper()
    else:
        out["protocol"] = "unknown"
    if "label" in out:
        out["label"] = out["label"].fillna("").astype(str)
    if "timestamp" in out:
        out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)
    if "duration" in sources and "us" in sources["duration"].lower():
        out["duration"] = out["duration"] / 1000.0
    return out, sources

def _external(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
        return not (parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_reserved)
    except ValueError:
        return False

def _entropy(values: pd.Series) -> float:
    counts = values.value_counts(normalize=True)
    return float(-(counts * np.log2(counts)).sum()) if len(counts) else 0.0

def extract_state(raw: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, Any]]:
    flows, source_fields = normalize_columns(raw)
    if flows.empty:
        raise ValueError("No flow records found in the CSV.")
    duration = flows["duration"].dropna()
    packets = flows["packets"].dropna()
    byte_values = flows["bytes"].dropna()
    syn = flows["syn"].fillna(0)
    ack = flows["ack"].fillna(0)
    span_seconds = 0.0
    if "timestamp" in flows and flows["timestamp"].notna().sum() >= 2:
        span_seconds = max(0.0, (flows["timestamp"].max() - flows["timestamp"].min()).total_seconds())
    pps = flows["packets"] / (flows["duration"].clip(lower=1) / 1000.0) if flows["duration"].notna().any() else pd.Series(dtype=float)
    values = {
        "flow_count": int(len(flows)),
        "unique_source_hosts": int(flows.loc[flows.src_ip.ne("unknown"), "src_ip"].nunique()),
        "unique_destination_hosts": int(flows.loc[flows.dst_ip.ne("unknown"), "dst_ip"].nunique()),
        "unique_destination_ports": int(flows["dst_port"].dropna().nunique()),
        "protocol_diversity": int(flows["protocol"].replace("unknown", np.nan).nunique()),
        "mean_flow_duration_ms": float(duration.mean()) if len(duration) else None,
        "median_flow_duration_ms": float(duration.median()) if len(duration) else None,
        "mean_packets_per_flow": float(packets.mean()) if len(packets) else None,
        "mean_bytes_per_flow": float(byte_values.mean()) if len(byte_values) else None,
        "total_bytes": float(byte_values.sum()) if len(byte_values) else None,
        "syn_to_ack_ratio": float(syn.sum() / (ack.sum() + 1.0)) if "syn" in source_fields or "ack" in source_fields else None,
        "syn_flow_ratio": float((syn.gt(0)).mean()) if "syn" in source_fields else None,
        "external_destination_ratio": float(flows.loc[flows.dst_ip.ne("unknown"), "dst_ip"].map(_external).mean()) if flows.dst_ip.ne("unknown").any() else None,
        "flows_per_source_p95": float(flows.groupby("src_ip").size().quantile(.95)) if flows.src_ip.ne("unknown").any() else None,
        "total_bytes_per_second": float(byte_values.sum() / span_seconds) if span_seconds > 0 and len(byte_values) else None,
        "mean_packets_per_second": float(pps.replace([np.inf, -np.inf], np.nan).dropna().mean()) if len(pps) else None,
        "destination_port_entropy": _entropy(flows.loc[flows.dst_port.notna(), "dst_port"].astype(str)) if flows.dst_port.notna().any() else None,
        "unique_host_pairs": int(flows.loc[flows.src_ip.ne("unknown") & flows.dst_ip.ne("unknown"), ["src_ip", "dst_ip"]].drop_duplicates().shape[0]),
    }
    vector = []
    for name, unit, cap, description in FEATURES:
        value = values[name]
        normalized = None if value is None or not math.isfinite(float(value)) else round(min(1.0, max(0.0, math.log1p(max(0.0, float(value))) / math.log1p(cap))), 4)
        vector.append({"name": name, "value": None if value is None else round(float(value), 4), "normalized": normalized, "unit": unit, "available": value is not None, "source": description})
    flows["duration_ms"] = flows["duration"]
    flows["source_field_map"] = None
    return flows, {"features": vector, "feature_count": len(vector), "source_fields": source_fields, "window": {"records": int(len(flows)), "timestamp_span_seconds": round(span_seconds, 3) if span_seconds else None}}
