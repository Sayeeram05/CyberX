<p align="center">
  <img src="https://img.shields.io/badge/Django-6.0-green?style=for-the-badge&logo=django" />
  <img src="https://img.shields.io/badge/Python-3.12+-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/PyTorch-2.0+-orange?style=for-the-badge&logo=pytorch" />
  <img src="https://img.shields.io/badge/scikit--learn-1.4+-yellow?style=for-the-badge&logo=scikit-learn" />
</p>

# CyberX — AI-Powered Cybersecurity Platform

CyberX is a full-stack Django web application that bundles **five independent security modules** into a single dashboard. Each module uses machine learning or rule-based analysis to detect threats in real time.

| Module                   | Technique                                                                | Accuracy / Coverage       |
| ------------------------ | ------------------------------------------------------------------------ | ------------------------- |
| **Email Validation**     | 9-layer pipeline (Regex · DNS · SPF · DKIM · DMARC · Blocklist · WHOIS)  | 5,100+ disposable domains |
| **URL Threat Detection** | 6-step pipeline · 3-model ensemble (DT · RF · ET) · binary Safe/Phishing | 95%+                      |
| **Phishing Detection**   | PyTorch deep-learning MLP (87 features)                                  | ~95%                      |
| **Malware Analysis**     | Signature + Heuristic (10 rules) + ML ensemble (RF · GB)                 | 100% on benchmark         |
| **Network IDS**          | Ensemble (RF + XGBoost) on 78 flow features · 7 attack classes           | 98%+                      |

---

## Project Structure

```
CyberX/
├── App/                              # Django project root
│   ├── manage.py
│   ├── db.sqlite3
│   ├── CyberX/                       # Settings & URL config
│   ├── Home/                         # Landing page
│   ├── EmailValidation/              # 9-layer email pipeline
│   ├── UrlThreadDetection/           # URL threat scanning (6-step + ensemble)
│   ├── PhisingDetection/             # Phishing URL detection (PyTorch MLP)
│   ├── MalwareAnalysis/              # Malware file analysis
│   ├── NetworkIDS/                   # Network intrusion detection
│   └── Frontend/                     # Shared templates & static assets
├── Services/                         # ML training notebooks & dataset artifacts
│   ├── EmailValidation/
│   ├── MalwareAnalysis/
│   ├── NetworkIDS/
│   ├── Phishing-detection/
│   └── URL threat scanning/
├── requirements.txt
└── README.md
```

Each `App/<Module>/README.md` contains module-specific architecture, API reference, and setup instructions.

---

## Quick Start

### 1. Clone & create virtual environment

```bash
git clone https://github.com/<your-username>/CyberX.git
cd CyberX
python -m venv env
```

### 2. Activate the environment

```bash
# Windows
env\Scripts\activate

# macOS / Linux
source env/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run migrations

```bash
cd App
python manage.py migrate
```

### 5. Start the development server

```bash
python manage.py runserver localhost:8000
```

Open http://localhost:8000 in your browser.

---

## Prerequisites

| Requirement                     | Version    | Notes                                                                    |
| ------------------------------- | ---------- | ------------------------------------------------------------------------ |
| **Python**                      | 3.12+      | [python.org/downloads](https://www.python.org/downloads/)                |
| **Git**                         | Any recent | [git-scm.com](https://git-scm.com/)                                      |
| **Npcap** _(Windows, optional)_ | Latest     | Only for Network IDS live-capture. Install with WinPcap-compatible mode. |

> **Windows + Network IDS live capture:** run your terminal as Administrator.

---

## Module READMEs

- [App/EmailValidation/README.md](App/EmailValidation/README.md)
- [App/UrlThreadDetection/README.md](App/UrlThreadDetection/README.md)
- [App/PhisingDetection/README.md](App/PhisingDetection/README.md)
- [App/MalwareAnalysis/README.md](App/MalwareAnalysis/README.md)
- [App/NetworkIDS/README.md](App/NetworkIDS/README.md)

---

## License

MIT
