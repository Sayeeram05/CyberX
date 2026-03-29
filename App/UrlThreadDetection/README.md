# URL Threat Detection — CyberX Module

Binary-classification URL scanner that labels every URL as **Safe** or **Phishing** through a 6-step weighted pipeline backed by a 3-model scikit-learn ensemble. Achieves 95%+ accuracy.

---

## Architecture

```
Input (URL string)
        │
        ▼
Step 1 — URL Normalization          (parse, clean, percent-decode)
        │
        ▼
Step 2 — Blocklist & IP Check       (known-bad patterns, shorteners, IP-in-URL)
        │                            → immediate Phishing verdict if matched
        ▼
Step 3 — Domain Analysis            (7-layer whitelist, WHOIS age, DNS)      ×0.20
        │
        ▼
Step 4 — URL Structure              (length, path depth, entropy, special chars) ×0.20
        │
        ▼
Step 5 — Reputation Heuristics      (brand spoofing, phishing keywords, TLD risk) ×0.20
        │
        ▼
Step 6 — ML Ensemble                (DT + RF + ET majority vote)              ×0.40
        │
        ▼
Risk Score = ml×0.40 + domain×0.20 + structure×0.20 + reputation×0.20
        │
        ▼
Result: Safe | Phishing  (0–100 risk score)
```

---

## Risk Levels

| Range  | Level              |
| ------ | ------------------ |
| 0–25   | Safe               |
| 26–50  | Low Risk           |
| 51–75  | Medium Risk        |
| 76–100 | High Risk/Phishing |

---

## ML Models (Step 6)

| Model         | Algorithm                | Role                               |
| ------------- | ------------------------ | ---------------------------------- |
| Decision Tree | `DecisionTreeClassifier` | Fast baseline, interpretable       |
| Random Forest | `RandomForestClassifier` | Bagging ensemble, reduces variance |
| Extra Trees   | `ExtraTreesClassifier`   | Extreme randomization, low bias    |

Trained on **Cisco Umbrella Top 1M** (safe) + **OpenPhish** + **PhishTank** (phishing). 80/20 stratified split.

---

## Feature Set (35+)

| Category         | Features                                                                          |
| ---------------- | --------------------------------------------------------------------------------- |
| URL structure    | `url_len`, `domain_len`, `path_len`, `path_depth`, `num_subdomains`               |
| Character counts | `num_dots`, `num_hyphens`, `num_special_chars`, `digit_ratio`, `domain_entropy`   |
| Domain signals   | `has_ip`, `https`, `suspicious_tld`, `is_shortener`, `has_port`                   |
| Content keywords | `has_login_keyword`, `has_secure_keyword`, `has_brand_keyword`, `has_obfuscation` |

---

## Key Files

| File                         | Purpose                                                           |
| ---------------------------- | ----------------------------------------------------------------- |
| `views.py`                   | Django view + 6-step pipeline orchestrator                        |
| `url_analyzer_production.py` | `URLThreatAnalyzer` — feature extraction, model loading, ensemble |
| `urls.py`                    | Route: `/urlthreatdetection/`                                     |
| `models.py`                  | Django DB models                                                  |

Models are loaded from `Services/URL threat scanning/models/` at runtime.

---

## API

### `POST /urlthreatdetection/`

| Field | Type   | Required | Description    |
| ----- | ------ | -------- | -------------- |
| `url` | string | Yes      | URL to analyze |

**Response (JSON)**

```json
{
  "url": "http://paypal-secure-login.xyz/verify",
  "prediction": "Phishing",
  "risk_score": 87,
  "risk_level": "High Risk",
  "pipeline_steps": {
    "domain_score": 90,
    "structure_score": 75,
    "reputation_score": 95,
    "ml_score": 85
  }
}
```

---

## Setup

### 1. Install Dependencies

```bash
pip install scikit-learn joblib tldextract dnspython
```

### 2. Train the Model _(optional — pre-trained models included)_

Open `Services/URL threat scanning/Main.ipynb` and run all cells. `.joblib` files are exported to `Services/URL threat scanning/models/`.

### 3. Run Server

```bash
cd App
python manage.py runserver
```
