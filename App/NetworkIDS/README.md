# CyberX — Network Intrusion Detection System (NIDS)

Real-time network intrusion detection powered by an ensemble ML classifier (RandomForest + XGBoost soft-voting).

## Features

| Feature                | Description                                                     |
| ---------------------- | --------------------------------------------------------------- |
| **PCAP Upload**        | Upload `.pcap` / `.pcapng` files from Wireshark/tcpdump         |
| **Live Capture**       | Sniff packets from a network interface (requires admin + Npcap) |
| **78 Flow Features**   | CICFlowMeter-compatible bidirectional flow statistics           |
| **7 Attack Classes**   | Benign, DoS, DDoS, PortScan, BruteForce, WebAttack, Botnet/C2   |
| **Polling UI**         | JS polls every 2 seconds for live progress                      |
| **Heuristic Fallback** | Rule-based classification when the ML model is not loaded       |

## Architecture

```
NetworkIDS/
├── models.py             # AnalysisSession Django model (persisted for polling)
├── flow_extractor.py     # PacketFlowExtractor — Scapy packets → 78 features
├── views.py              # Views + lazy model loader + background threads
├── urls.py               # /networkids/, /start/, /status/<id>/, /results/<id>/
├── admin.py              # Django admin registration
├── apps.py               # NetworkIDSConfig
├── models/               # Trained model artifacts
│   ├── nids_model.joblib
│   ├── nids_scaler.joblib
│   ├── nids_feature_names.json
│   └── nids_label_encoder.json
└── migrations/
```

## Setup

### 1. Install Dependencies

```bash
pip install scapy xgboost netifaces
```

For **live packet capture** on Windows, install [Npcap](https://npcap.com/) with "WinPcap API-compatible mode" enabled.

### 2. Train the Model

Open `Services/NetworkIDS/model.ipynb` and run all cells:

1. Download CICIDS2017 CSVs from [UNB](https://www.unb.ca/cic/datasets/ids-2017.html)
2. Place them in `Services/NetworkIDS/Dataset/`
3. Run the notebook — it saves `.joblib` files to both `Services/NetworkIDS/models/` and `App/NetworkIDS/models/`

### 3. Run Migrations

```bash
cd App
python manage.py makemigrations NetworkIDS
python manage.py migrate NetworkIDS
```

### 4. Start Server

```bash
python manage.py runserver localhost:8000
```

Visit http://localhost:8000/networkids/

## API

### POST `/networkids/api/analyze/`

Upload a PCAP file for synchronous analysis:

```bash
curl -X POST -F "pcap_file=@capture.pcap" http://localhost:8000/networkids/api/analyze/
```

Response:

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

### POST `/networkids/start/`

Start async analysis (returns `session_id` for polling):

```bash
curl -X POST -F "source_type=pcap_upload" -F "pcap_file=@capture.pcap" http://localhost:8000/networkids/start/
```

### GET `/networkids/status/<session_id>/`

Poll for progress (call every 2 seconds).
