"""FastAPI application for GUARD's local flow analyzer."""
from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .features import extract_state
from .graph import build_graph
from .scoring import score_flows

ROOT = Path(__file__).resolve().parent.parent
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_ROWS = 100_000

app = FastAPI(title="GUARD Network State Analyzer", version="1.0.0", description="Flow telemetry → feature vector + host graph + batch-relative anomaly scores")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
app.mount("/data", StaticFiles(directory=ROOT / "data"), name="data")

@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(ROOT / "static" / "index.html")

@app.get("/api/health")
def health():
    return {"status": "ok", "analyzer": "flow CSV", "state_representation": {"feature_vector_dimensions": 18, "directed_host_graph": True}, "scoring": "batch-relative Isolation Forest when at least 12 flow records are available", "packet_capture": "optional; install requirements-capture.txt and run with interface permissions"}

@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=415, detail="Upload a .csv flow telemetry file.")
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="CSV exceeds the 20 MB upload limit.")
    if not data:
        raise HTTPException(status_code=400, detail="The uploaded CSV is empty.")
    try:
        raw = pd.read_csv(BytesIO(data), nrows=MAX_ROWS + 1, low_memory=False)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not parse CSV: {exc}") from exc
    if len(raw) > MAX_ROWS:
        raise HTTPException(status_code=413, detail=f"CSV exceeds the {MAX_ROWS:,} flow row limit.")
    try:
        flows, state = extract_state(raw)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if "src_ip" not in flows or "dst_ip" not in flows:
        raise HTTPException(status_code=422, detail="Source IP and Destination IP columns are required.")
    if state["source_fields"].get("src_ip") is None or state["source_fields"].get("dst_ip") is None:
        raise HTTPException(status_code=422, detail="Could not identify source and destination IP columns. See README for accepted headers.")
    scored, model = score_flows(flows)
    graph = build_graph(flows, scored)
    flagged = sum(1 for flow in scored if flow["flagged"])
    return {
        "filename": file.filename,
        "summary": {"flow_count": len(flows), "unique_hosts": graph["node_count"], "graph_edges": graph["edge_count"], "flagged_flows": flagged, "score_available": model["available"]},
        "state": state,
        "graph": graph,
        "scoring": model,
        "flows": scored[:500],
        "flows_returned": min(len(scored), 500),
        "flows_truncated": len(scored) > 500,
    }
