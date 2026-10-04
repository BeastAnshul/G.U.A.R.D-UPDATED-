"""Batch-relative anomaly scoring for network flow records."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

NUMERIC = ["src_port", "dst_port", "duration", "packets", "bytes", "syn", "ack"]

def score_flows(flows: pd.DataFrame) -> tuple[list[dict], dict]:
    frame = flows.copy()
    n = len(frame)
    if n < 12:
        return [], {"available": False, "method": "Isolation Forest", "reason": "At least 12 flow records are required for batch-relative scoring.", "scored_flows": 0}
    matrix = frame[NUMERIC].copy()
    matrix = matrix.fillna(matrix.median()).fillna(0)
    for col in ("duration", "packets", "bytes", "src_port", "dst_port"):
        matrix[col] = np.log1p(matrix[col].clip(lower=0))
    scaler = RobustScaler()
    x = scaler.fit_transform(matrix)
    if np.all(np.nanstd(x, axis=0) < 1e-12):
        return [], {"available": False, "method": "Isolation Forest", "reason": "The uploaded numeric flow fields have no variation to compare.", "scored_flows": 0}
    model = IsolationForest(n_estimators=160, contamination="auto", random_state=42, n_jobs=-1)
    model.fit(x)
    normality = model.score_samples(x)
    # Convert relative ranks into interpretable 0–100 batch-relative scores.
    order = pd.Series(normality).rank(method="average", pct=True).to_numpy()
    risk = np.round((1.0 - order) * 100.0, 1)
    top_count = max(1, int(np.ceil(n * 0.05)))
    flagged_idx = set(np.argsort(normality)[:top_count].tolist())
    result = []
    for i, (_, row) in enumerate(frame.iterrows()):
        result.append({
            "flow_id": i + 1,
            "source_ip": str(row.src_ip), "destination_ip": str(row.dst_ip),
            "source_port": _number(row.src_port), "destination_port": _number(row.dst_port),
            "protocol": str(row.protocol), "packets": _number(row.packets), "bytes": _number(row.bytes),
            "duration_ms": _number(row.duration_ms), "label": str(row.get("label", "") or ""),
            "anomaly_score": float(risk[i]), "flagged": i in flagged_idx,
        })
    result.sort(key=lambda item: item["anomaly_score"], reverse=True)
    return result, {"available": True, "method": "Isolation Forest", "scope": "uploaded batch", "training_rows": n, "scored_flows": n, "flagged_flows": top_count, "flag_rule": "Highest 5% of relative anomaly scores in this upload (at least one flow).", "random_state": 42}

def _number(value):
    if pd.isna(value):
        return None
    try:
        return float(value) if float(value) % 1 else int(value)
    except (TypeError, ValueError):
        return None
