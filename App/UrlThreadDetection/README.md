# URL Threat Detection — CyberX Module

## Overview

Binary classification URL scanner that labels every URL as **Safe** or **Phishing** through a 6-step analysis pipeline backed by a 3-model scikit-learn ensemble.

---

## Architecture

```
POST /urlthreatdetection/
        │
        ▼
┌──────────────────────────────────┐
│  views.py — Pipeline Orchestrator │
│  (6 sequential steps)            │
└──────────┬───────────────────────┘
           │
           ▼
┌──────────────────────────────────┐
│  url_analyzer_production.py      │
│  URLThreatAnalyzer class         │
│  • Feature extraction (35+)      │
│  • 3-model ensemble prediction   │
│  • Trusted-domain whitelist      │
└──────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────┐
│  Services/URL threat scanning/   │
│  models/                         │
│  • Decision_Tree_*.joblib        │
│  • Random_Forest_*.joblib        │
│  • Extra_Trees_*.joblib          │
└──────────────────────────────────┘
```

---

## 6-Step Pipeline

| Step | Name                      | Description                                                  | Scored?         |
| ---- | ------------------------- | ------------------------------------------------------------ | --------------- |
| 1    | **URL Normalization**     | Parse, clean, decode the raw URL                             | No              |
| 2    | **Blocklist & IP Check**  | Match against known-bad patterns, shortener lists, IP-in-URL | Pre-filter only |
| 3    | **Domain Analysis**       | 7-layer trusted whitelist + WHOIS age + DNS resolution       | Yes (20%)       |
| 4    | **URL Structure**         | Length, depth, entropy, special-char ratios                  | Yes (20%)       |
| 5    | **Reputation Heuristics** | Brand spoofing, phishing keywords, TLD risk                  | Yes (20%)       |
| 6    | **ML Classification**     | 3-model ensemble (DT · RF · ET), majority vote               | Yes (40%)       |

### Risk Score Formula

```
risk = ml_score × 0.40
     + domain_score × 0.20
     + structure_score × 0.20
     + reputation_score × 0.20
```

Each component outputs 0–100; the weighted sum produces the final risk score.

---

## Classification

| Label        | Code | Meaning                         |
| ------------ | ---- | ------------------------------- |
| **Safe**     | 0    | No threats detected             |
| **Phishing** | 1    | Likely malicious / phishing URL |

### Threat Levels

| Risk Range | Level                | Color  |
| ---------- | -------------------- | ------ |
| 0–25       | Safe                 | Green  |
| 26–50      | Low Risk             | Yellow |
| 51–75      | Medium Risk          | Orange |
| 76–100     | High Risk / Phishing | Red    |

---

## Key Files

| File                         | Purpose                                                                            |
| ---------------------------- | ---------------------------------------------------------------------------------- |
| `views.py`                   | Django view + 6-step pipeline orchestrator                                         |
| `url_analyzer_production.py` | `URLThreatAnalyzer` class — feature extraction, model loading, ensemble prediction |
| `urls.py`                    | Route: `/urlthreatdetection/`                                                      |
| `models.py`                  | Django DB models (currently unused)                                                |

---

## Training Data

| Source                    | Role                   |
| ------------------------- | ---------------------- |
| **Cisco Umbrella Top 1M** | Legitimate (Safe) URLs |
| **OpenPhish**             | Phishing URLs          |
| **PhishTank**             | Phishing URLs          |

Training notebook: `Services/URL threat scanning/Main.ipynb`

---

## Feature Summary (35+)

**URL Structure:** url_length, domain_length, path_length, path_depth, query_length, fragment_length, num_subdomains

**Character Analysis:** num_dots, num_hyphens, num_underscores, num_slashes, num_special_chars, num_digits, digit_ratio, letter_ratio, domain_entropy

**Domain Intelligence:** has_ip_address, is_https, suspicious_tld, is_url_shortener, has_port

**Content Indicators:** has_login_keyword, has_secure_keyword, has_brand_keyword, suspicious_word_count, has_obfuscation

---

## API

### `GET /urlthreatdetection/`

Returns the analysis form page.

### `POST /urlthreatdetection/`

**Request body:** `url=<target_url>` (form-encoded)

**Response:** Rendered HTML with:

- Overall risk score (0–100)
- Threat label (Safe / Phishing)
- 6-step pipeline results with per-step status
- Risk breakdown by component (ML, Domain, Structure, Reputation)
- Individual model predictions and confidence
- Domain intelligence (WHOIS age, registrar, DNS IPs)
- Threat indicators and recommendations

### `POST /urlthreatdetection/api/`

**Request body:** `url=<target_url>` (form-encoded)

**Response:** JSON

```json
{
  "url": "https://example.com",
  "risk_score": 12,
  "threat_level": "safe",
  "threat_label": "Safe",
  "pipeline_steps": [ ... ],
  "risk_breakdown": [ ... ],
  "model_predictions": { ... },
  "domain_info": { ... },
  "threat_indicators": [ ... ],
  "recommendations": [ ... ]
}
```

---

## Model Files

Place these in `Services/URL threat scanning/models/`:

```
Decision_Tree_Classifier_URL_Threat_Detection.joblib
Random_Forest_Classifier_URL_Threat_Detection.joblib
Extra_Trees_Classifier_URL_Threat_Detection.joblib
```

Models are lazy-loaded on first request and cached for the process lifetime.

---

## Dependencies

- `scikit-learn` — ML models
- `joblib` — Model serialization
- `tld` — TLD extraction and validation
- `python-whois` — WHOIS lookups
- `dnspython` — DNS resolution
- `numpy` — Feature arrays
