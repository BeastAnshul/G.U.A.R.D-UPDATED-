# GUARD — Network State Analyzer

GUARD is a local network telemetry prototype for turning network flows into an inspectable network state. It ingests a flow CSV, extracts an 18-dimensional feature vector, builds a directed host communication graph, and scores unusual flows against the uploaded batch with an Isolation Forest.

The dashboard is backed by a Python API. The scores are batch-relative anomaly indicators, not predictions from a pretrained production security model. No packet payloads are stored. Optional packet capture is off by default and requires permission to monitor the selected network interface.

## What it does

- Parses common flow CSV headers, including CICFlowMeter-style fields.
- Produces an 18-feature raw and normalized network-state vector.
- Builds a directed graph where hosts are nodes and observed flows are weighted edges.
- Computes host and graph statistics, including degree, density, and connected components.
- Applies Isolation Forest to flow-level numeric features when enough rows are available; otherwise reports that scoring is unavailable.
- Shows flagged flows, feature values, and graph topology in the browser.
- Optionally captures packet metadata locally with Scapy and exports flow records to CSV.

## Run locally

Requires Python 3.10 or later.

```bash
python -m venv .venv
```

Activate the environment, then install dependencies. On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

On Linux or macOS:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the API and dashboard:

```bash
uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000>. The API documentation is at <http://127.0.0.1:8000/docs>.

Upload your own flow CSV using **Analyze flow CSV**. A small example file is included at `data/sample_flows.csv`.

The sample file contains fictional RFC documentation-range addresses and is only for a smoke test; it is not live network traffic.

## How network state is represented

For every upload, GUARD builds both representations requested in the challenge:

1. **Feature vector:** `S[t] ∈ R¹⁸`, with a raw value, unit, source explanation, and log-scaled value normalized to `[0, 1]` for each available feature. Missing source columns remain `n/a` instead of being presented as measured values.
2. **Communication graph:** directed graph `G[t] = (V, E)`, where each host is a node and each observed source-to-destination pair is an edge. Edges include flow count, bytes, packets, protocols, and relative anomaly score. Host nodes show in-degree, out-degree, and mean incident anomaly score.

The 18 vector features are: flow count, unique source hosts, unique destination hosts, unique destination ports, protocol diversity, mean and median duration, mean packets per flow, mean bytes per flow, total bytes, SYN/ACK ratio, SYN flow ratio, external destination ratio, 95th percentile flows per source, aggregate bytes per second, mean packets per second, destination-port entropy, and unique directed host pairs.

## Technology and pipeline

| Part | Technology | Role |
| --- | --- | --- |
| API | FastAPI + Uvicorn | Receives CSV uploads, validates them, returns analysis JSON, and serves the dashboard. |
| Data processing | Pandas + NumPy | Parses flow records, handles missing fields, and computes network state features. |
| Anomaly scoring | scikit-learn Isolation Forest + RobustScaler | Compares numeric flows with the other flows in the current upload. |
| Graph analysis | NetworkX | Builds the directed host graph and calculates density and connected components. |
| Optional local capture | Scapy | Captures packet metadata and aggregates it into flow CSV; packet payload is not stored. |
| User interface | HTML, CSS, JavaScript, SVG | Uploads telemetry to the API and visualizes the returned vector, graph, and findings. |

```text
authorized interface (optional) → Scapy flow CSV ─┐
uploaded flow CSV ──────────────────────────────────┴→ FastAPI → Pandas/NumPy feature extraction
                                                              ├→ 18D state vector
                                                              ├→ NetworkX host graph
                                                              └→ Isolation Forest scores → dashboard
```

GitHub Actions runs the unit tests and Python compile check on pushes and pull requests.

## CSV fields

At minimum, include source and destination IP columns. Recognized aliases include `Source IP` / `Src IP`, `Destination IP` / `Dst IP`, `Protocol`, `Source Port`, `Destination Port`, `Flow Duration`, `Total Fwd Packets`, `Total Length of Fwd Packets`, `SYN Flag Count`, `ACK Flag Count`, `Timestamp`, and `Label`.

Missing optional columns are treated as unavailable, not silently presented as measured values. The 18 state features are emitted with their raw values, normalized values, units, and a note when a source field was unavailable.

## Optional authorized packet capture

Install Scapy (included in `requirements-capture.txt`) and run capture only on a network/interface you are authorized to monitor. Capture stores flow metadata (IPs, ports, protocol, packet/byte counts, TCP flags, and time range), not packet payloads.

```bash
sudo python -m app.capture --interface wlan0 --duration 60 --output data/captured_flows.csv
```

On Windows, run a terminal with the required capture permissions and install Npcap. Interface names vary by machine. Then upload `data/captured_flows.csv` in the dashboard.

## Repository layout

```text
app/
  capture.py       Optional metadata-only Scapy flow capture
  features.py      Flow parsing and 18-feature state construction
  graph.py         Directed host graph construction and metrics
  main.py          FastAPI endpoints and static dashboard serving
  scoring.py       Batch-relative Isolation Forest scoring
static/
  index.html       Dashboard UI connected to the API
data/
  sample_flows.csv Example input telemetry
```

## API

- `GET /api/health` — API and model capability status.
- `POST /api/analyze` — multipart upload of a flow CSV; returns state vector, graph, metrics, and scored flows.
- `GET /docs` — interactive OpenAPI documentation.

## Important interpretation

This repository demonstrates a real telemetry-processing path, but it is not a validated IDS and should not be used to automatically block or isolate devices. Isolation Forest is fitted to the current uploaded batch, so scores mean “unusual relative to this batch.” Reliable forecasting of future attack stages requires a labeled, time-ordered dataset and a trained temporal model; this prototype does not claim to provide that. Review all findings with an analyst.

## License

MIT License. See `LICENSE`.
