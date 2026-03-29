<p align="center">
  <img src="https://img.shields.io/badge/Django-6.0-green?style=for-the-badge&logo=django" />
  <img src="https://img.shields.io/badge/Python-3.12+-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/PyTorch-2.0+-orange?style=for-the-badge&logo=pytorch" />
  <img src="https://img.shields.io/badge/scikit--learn-1.4+-yellow?style=for-the-badge&logo=scikit-learn" />
</p>

# CyberX — AI-Powered Cybersecurity Platform

CyberX is a full-stack Django web application that bundles **five independent security modules** into a single dashboard. Each module uses machine-learning or rule-based analysis to detect threats in real time.

| Module                   | Technique                                                                | Key Metric                       |
| ------------------------ | ------------------------------------------------------------------------ | -------------------------------- |
| **Email Validation**     | 9-layer pipeline (Regex · DNS · SPF · DKIM · DMARC · Blocklist · WHOIS)  | 5 100+ disposable domains        |
| **URL Threat Detection** | 6-step pipeline · 3-model ensemble (DT · RF · ET) · binary Safe/Phishing | 95%+ accuracy                    |
| **Phishing Detection**   | PyTorch deep-learning MLP (87 features)                                  | ~95% accuracy                    |
| **Malware Analysis**     | Signature + Heuristic + ML (RF · GB)                                     | 100% ML accuracy                 |
| **Network IDS**          | Ensemble (RF + XGBoost) on 78 flow features                              | 98%+ accuracy · 7 attack classes |

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Project Structure](#project-structure)
3. [Quick Start](#quick-start)
4. [Module Overview](#module-overview)
5. [API Endpoints](#api-endpoints)
6. [Configuration](#configuration)
7. [Troubleshooting](#troubleshooting)
8. [Contributing](#contributing)
9. [License](#license)

---

## Prerequisites

| Requirement                     | Version    | Notes                                                                                                                     |
| ------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------- |
| **Python**                      | 3.12+      | [python.org/downloads](https://www.python.org/downloads/)                                                                 |
| **pip**                         | Latest     | Ships with Python                                                                                                         |
| **Git**                         | Any recent | [git-scm.com](https://git-scm.com/)                                                                                       |
| **Npcap** _(Windows, optional)_ | Latest     | Only for Network IDS live-capture. [npcap.com](https://npcap.com/) — install with _"WinPcap API-compatible Mode"_ checked |

> **Windows users:** Run your terminal as Administrator if you plan to use the Network IDS live-capture feature.

---

## Project Structure

```
CyberX/
├── App/                              # Django project root
│   ├── manage.py
│   ├── db.sqlite3
│   ├── CyberX/                       # Settings & URL config
│   │   ├── settings.py
│   │   ├── urls.py
│   │   └── wsgi.py / asgi.py
│   ├── Home/                         # Landing page
│   ├── EmailValidation/              # Email validation (9-layer pipeline)
│   ├── UrlThreadDetection/           # URL threat scanning (6-step pipeline)
│   ├── PhisingDetection/             # Phishing URL detection (PyTorch)
│   │   └── models/                   # .pth + .joblib + .json
│   ├── MalwareAnalysis/              # Malware file analysis
│   ├── NetworkIDS/                   # Network intrusion detection
│   │   └── models/                   # .joblib + .json
│   └── Frontend/                     # Shared templates & static assets
│       ├── templates/                # Django HTML templates
│       └── static/
│           ├── css/                  # main.css · services.css · per-module CSS
│           └── js/                   # Per-module JS
├── Services/                         # ML training notebooks & artifacts
│   ├── EmailValidation/
│   ├── MalwareAnalysis/
│   │   ├── model.ipynb
│   │   └── models/                   # Trained models (loaded at runtime)
│   ├── NetworkIDS/
│   │   ├── model.ipynb
│   │   └── Dataset/
│   ├── Phishing-detection/
│   │   ├── Model.ipynb
│   │   └── Dataset/
│   └── URL threat scanning/
│       ├── Main.ipynb                # Binary classification notebook
│       └── models/                   # DT · RF · ET .joblib files
├── requirements.txt
└── .gitignore
```

---

## Quick Start

### 1. Clone & Create Virtual Environment

```bash
git clone https://github.com/<your-username>/CyberX.git
cd CyberX
python -m venv env
```

**Activate the environment:**

```powershell
# Windows PowerShell
.\env\Scripts\Activate.ps1

# macOS / Linux
source env/bin/activate
```

### 2. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

> **PyTorch GPU (optional):** The default installation is CPU-only. For GPU acceleration in the Phishing Detection module, install with CUDA support:
>
> ```bash
> pip install torch --index-url https://download.pytorch.org/whl/cu121
> ```

### 3. Train ML Models

Each service has a Jupyter notebook that trains and exports the required model files:

| Module                   | Notebook                                  | Output                                        |
| ------------------------ | ----------------------------------------- | --------------------------------------------- |
| **URL Threat Detection** | `Services/URL threat scanning/Main.ipynb` | `Services/URL threat scanning/models/`        |
| **Phishing Detection**   | `Services/Phishing-detection/Model.ipynb` | Copy output to `App/PhisingDetection/models/` |
| **Malware Analysis**     | `Services/MalwareAnalysis/model.ipynb`    | `Services/MalwareAnalysis/models/`            |
| **Network IDS**          | `Services/NetworkIDS/model.ipynb`         | Copy output to `App/NetworkIDS/models/`       |

```bash
pip install jupyter
jupyter notebook
```

Open each notebook and **Run All Cells**. Email Validation requires no ML models.

### 4. Apply Migrations & Run

```bash
cd App
python manage.py migrate
python manage.py runserver
```

Open **http://127.0.0.1:8000/** — all five services are accessible from the navigation bar.

---

## Module Overview

### Email Validation

**Route:** `/emailvalidation/` · **No ML models required**

9-layer validation pipeline with weighted risk scoring:

| Layer | Check                                | Weight |
| ----- | ------------------------------------ | ------ |
| 1     | Regex format (RFC 5322)              | —      |
| 2     | `email-validator` library            | —      |
| 3     | Disposable-domain blocklist (5 100+) | 30%    |
| 4     | Temporary-email heuristics           | —      |
| 5     | WHOIS domain age                     | 15%    |
| 6     | SPF record                           | 15%    |
| 7     | DKIM signature                       | 10%    |
| 8     | DMARC policy                         | 10%    |
| 9     | MX / DNS deliverability              | 10%    |

Risk score: 0 (safe) to 100 (maximum risk).

---

### URL Threat Detection

**Route:** `/urlthreatdetection/`

6-step analysis pipeline with binary classification (**Safe** vs **Phishing**):

| Step | Name                  | Role                                                           |
| ---- | --------------------- | -------------------------------------------------------------- |
| 1    | URL Normalization     | Parse · clean · decode                                         |
| 2    | Blocklist & IP Check  | Known-bad patterns · shorteners · IP-in-URL (pre-filter)       |
| 3    | Domain Analysis       | Trusted whitelist (7-layer) + WHOIS age + DNS                  |
| 4    | URL Structure         | Length · depth · entropy · special chars                       |
| 5    | Reputation Heuristics | Brand spoofing · keywords · TLD risk                           |
| 6    | ML Classification     | 3-model ensemble (Decision Tree · Random Forest · Extra Trees) |

**Risk Score** = `ML × 0.4 + Domain × 0.2 + Structure × 0.2 + Reputation × 0.2`

**Datasets:** Cisco Umbrella Top 1M (legitimate) + OpenPhish + PhishTank (phishing).

**Model files:** 3 `.joblib` files in `Services/URL threat scanning/models/`

---

### Phishing Detection

**Route:** `/phishingdetection/`

PyTorch MLP neural network (87 → 300 → 100 → 1 sigmoid):

- 87 features: URL structure, HTML content, WHOIS age, domain entropy, brand impersonation
- Feature extraction via `tldextract`, `BeautifulSoup`, `python-whois`
- Fallback: heuristic scoring if model files are missing

**Model files:** `phishing_model.pth`, `phishing_scaler.joblib`, `feature_names.json` in `App/PhisingDetection/models/`

---

### Malware Analysis

**Route:** `/malwareanalysis/`

Three-engine malware scanner:

1. **Signature-based** — MD5/SHA hash matching against known malware
2. **Heuristic analysis** — 10 behavioral rules (entropy, packed sections, suspicious imports)
3. **Machine Learning** — Random Forest + Gradient Boosting ensemble (41 features)

Supports any file type; PE files (`.exe`, `.dll`) get deeper analysis via `pefile`.

**Model files:** `malware_rf_model.joblib`, `malware_gb_model.joblib`, `malware_scaler.joblib`, `malware_feature_names.json` in `Services/MalwareAnalysis/models/`

---

### Network IDS

**Route:** `/networkids/`

Real-time network intrusion detection with two input modes:

- **PCAP Upload** — `.pcap`, `.pcapng`, `.cap` files
- **Live Capture** — sniff from a network interface (requires admin + Npcap on Windows)

Extracts 78 CICFlowMeter-compatible bidirectional flow features and classifies into 7 classes: **Benign · DoS · DDoS · Port Scan · Brute Force · Web Attack · Botnet/C2**.

**Model files:** `nids_model.joblib`, `nids_scaler.joblib`, `nids_feature_names.json`, `nids_label_encoder.json` in `App/NetworkIDS/models/`

---

## API Endpoints

| Method       | URL                    | Description                       |
| ------------ | ---------------------- | --------------------------------- |
| `GET`        | `/`                    | Dashboard                         |
| `GET / POST` | `/emailvalidation/`    | Email validation                  |
| `GET / POST` | `/urlthreatdetection/` | URL threat scanner                |
| `GET / POST` | `/phishingdetection/`  | Phishing detector                 |
| `GET / POST` | `/malwareanalysis/`    | Malware file analysis             |
| `GET / POST` | `/networkids/`         | Network IDS (PCAP + live capture) |

All endpoints accept `GET` for the form and `POST` for analysis.

---

## Configuration

Key settings in `App/CyberX/settings.py`:

| Setting                       | Default   | Description                            |
| ----------------------------- | --------- | -------------------------------------- |
| `DEBUG`                       | `True`    | Set to `False` in production           |
| `ALLOWED_HOSTS`               | `['*']`   | Restrict in production                 |
| `DATA_UPLOAD_MAX_MEMORY_SIZE` | 100 MB    | Max upload size for PCAP/malware files |
| Database                      | SQLite    | Switch to PostgreSQL for production    |
| Cache                         | DB-backed | `cyberx_cache_table` with 10-min TTL   |

---

## Troubleshooting

| Problem                                         | Solution                                                                              |
| ----------------------------------------------- | ------------------------------------------------------------------------------------- |
| `ModuleNotFoundError: No module named 'django'` | Activate the virtual environment: `.\env\Scripts\Activate.ps1`                        |
| `ModuleNotFoundError: No module named 'scapy'`  | `pip install scapy` (Network IDS only)                                                |
| Models not loading / "ML model not loaded"      | Ensure model files are in the correct directories — see [Step 3](#3-train-ml-models)  |
| Network IDS live capture fails (Windows)        | Install [Npcap](https://npcap.com/) with WinPcap mode · run terminal as Administrator |
| Network IDS live capture fails (Linux)          | `sudo python manage.py runserver`                                                     |
| PyTorch CUDA errors without GPU                 | `pip install torch --index-url https://download.pytorch.org/whl/cpu`                  |
| Port 8000 in use                                | `python manage.py runserver 8080`                                                     |
| Static files not loading                        | `python manage.py collectstatic`                                                      |

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -m "Add your feature"`
4. Push: `git push origin feature/your-feature`
5. Open a Pull Request

---

## License

This project is for educational and research purposes.
