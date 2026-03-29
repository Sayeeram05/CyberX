# Network Intrusion Detection System — CyberX Module

Real-time network intrusion detection using an ensemble ML classifier (Random Forest + XGBoost soft-voting) trained on 78 bidirectional flow features.

---

## Architecture

```
Input (PCAP upload or live capture)
        │
        ▼
PacketFlowExtractor (flow_extractor.py)
  • Scapy packet parsing
  • Bidirectional flow assembly
  • 78 CICFlowMeter-compatible features
        │
        ▼
ML Ensemble
  • RandomForest  (joblib)
  • XGBoost       (joblib)
  • Soft-voting combination
        │
        ▼
Result: Benign | DoS | DDoS | PortScan | BruteForce | WebAttack | Botnet
```

---

## Attack Classes

| Class        | Description                             |
| ------------ | --------------------------------------- |
| `Benign`     | Normal traffic                          |
| `DoS`        | Denial-of-Service flood                 |
| `DDoS`       | Distributed Denial-of-Service           |
| `PortScan`   | Reconnaissance / port scanning          |
| `BruteForce` | SSH / FTP / HTTP credential attacks     |
| `WebAttack`  | SQL injection, XSS, directory traversal |
| `Botnet`     | C2 communication                        |

**Model accuracy:** 98%+ on CICIDS2017 benchmark.

---

## Key Files

| File                | Purpose                                                                                         |
| ------------------- | ----------------------------------------------------------------------------------------------- |
| `views.py`          | Django views — async task dispatch, polling endpoint, results page                              |
| `flow_extractor.py` | `PacketFlowExtractor` — Scapy → 78 flow features                                                |
| `models.py`         | `AnalysisSession` Django model (persists state for JS polling)                                  |
| `urls.py`           | Routes: `/networkids/`, `/start/`, `/status/<id>/`, `/results/<id>/`                            |
| `models/`           | `nids_model.joblib`, `nids_scaler.joblib`, `nids_feature_names.json`, `nids_label_encoder.json` |

---

## API

### `POST /networkids/api/analyze/` — Synchronous

Upload a PCAP file and receive results immediately.

```bash
curl -X POST -F "pcap_file=@capture.pcap" http://localhost:8000/networkids/api/analyze/
```

```json
{
  "status": "complete",
  "total_flows": 142,
  "malicious_flows": 3,
  "benign_flows": 139,
  "threat_score": 2.1,
  "results": [...]
}
```

### `POST /networkids/start/` — Async

Returns a `session_id` for polling.

```bash
curl -X POST -F "source_type=pcap_upload" -F "pcap_file=@capture.pcap" \
     http://localhost:8000/networkids/start/
```

### `GET /networkids/status/<session_id>/` — Poll

JS polls every 2 seconds. Returns `{ "status": "processing"|"complete"|"error", "progress": 0–100 }`.

---

## Setup

### 1. Install Dependencies

```bash
pip install scapy xgboost netifaces
```

For **live packet capture on Windows**, install [Npcap](https://npcap.com/) with _WinPcap API-compatible mode_ enabled and run your terminal as Administrator.

### 2. Train the Model

1. Download CICIDS2017 CSVs from [UNB](https://www.unb.ca/cic/datasets/ids-2017.html) and place in `Services/NetworkIDS/Dataset/`.
2. Open `Services/NetworkIDS/model.ipynb` and run all cells — artifacts are saved to `App/NetworkIDS/models/`.

### 3. Run Migrations & Server

```bash
cd App
python manage.py migrate NetworkIDS
python manage.py runserver
```
