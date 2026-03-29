# CyberX URL Threat Detection — Training & Model Service

## Overview

This directory contains the **Jupyter training notebook** and **exported model files** for the URL Threat Detection module. The system uses **binary classification** (Safe vs Phishing) with a 3-model scikit-learn ensemble trained on Cisco Umbrella + OpenPhish + PhishTank data.

---

## Directory Structure

```
URL threat scanning/
├── Main.ipynb          # Full training pipeline notebook
├── README.md           # This file
└── models/             # Exported .joblib model files
    ├── Decision_Tree_Classifier_URL_Threat_Detection.joblib
    ├── Random_Forest_Classifier_URL_Threat_Detection.joblib
    └── Extra_Trees_Classifier_URL_Threat_Detection.joblib
```

---

## Training Pipeline (Main.ipynb)

The notebook runs end-to-end in the following stages:

### 1. Data Collection

| Source                    | Label        | Purpose                          |
| ------------------------- | ------------ | -------------------------------- |
| **Cisco Umbrella Top 1M** | Safe (0)     | High-confidence legitimate URLs  |
| **OpenPhish**             | Phishing (1) | Active phishing URLs (live feed) |
| **PhishTank**             | Phishing (1) | Community-verified phishing URLs |

The notebook downloads from public APIs and merges into a single balanced DataFrame with columns `url` and `label`.

### 2. Feature Extraction (35+ Features)

Features are grouped into four categories:

#### URL Structure

| Feature          | Description               |
| ---------------- | ------------------------- |
| `url_len`        | Total URL character count |
| `domain_len`     | Domain name length        |
| `path_len`       | URL path length           |
| `path_depth`     | Number of `/` segments    |
| `query_len`      | Query string length       |
| `fragment_len`   | Fragment length           |
| `num_subdomains` | Subdomain count           |
| `hostname_len`   | Hostname length           |

#### Character Analysis

| Feature             | Description                                                                     |
| ------------------- | ------------------------------------------------------------------------------- |
| `num_dots`          | Dot count in full URL                                                           |
| `num_hyphens`       | Hyphen count                                                                    |
| `num_underscores`   | Underscore count                                                                |
| `num_slashes`       | Forward-slash count                                                             |
| `num_special_chars` | Special character count (`@`, `?`, `=`, `#`, `%`, `~`, `&`, `!`, `+`, `*`, `$`) |
| `num_digits`        | Digit count                                                                     |
| `digit_ratio`       | Digits ÷ total length                                                           |
| `letter_ratio`      | Letters ÷ total length                                                          |
| `domain_entropy`    | Shannon entropy of domain string                                                |

#### Domain Intelligence

| Feature          | Type   | Description                                                    |
| ---------------- | ------ | -------------------------------------------------------------- |
| `has_ip`         | Binary | URL uses IP address instead of domain                          |
| `https`          | Binary | URL uses HTTPS                                                 |
| `suspicious_tld` | Binary | TLD in high-risk set (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, etc.) |
| `is_shortener`   | Binary | Known URL shortener (bit.ly, t.co, etc.)                       |
| `has_port`       | Binary | Non-standard port specified                                    |

#### Content Indicators

| Feature                 | Type    | Description                                              |
| ----------------------- | ------- | -------------------------------------------------------- |
| `has_login_keyword`     | Binary  | Contains login/signin/account                            |
| `has_secure_keyword`    | Binary  | Contains secure/verify/update                            |
| `has_brand_keyword`     | Binary  | Contains known brand names (PayPal, Apple, Google, etc.) |
| `suspicious_word_count` | Numeric | Count of phishing keywords                               |
| `has_obfuscation`       | Binary  | URL encoding or obfuscation detected                     |

### 3. Model Training

Three classifiers are trained independently:

| Model             | Algorithm                | Key Behavior                         |
| ----------------- | ------------------------ | ------------------------------------ |
| **Decision Tree** | `DecisionTreeClassifier` | Fast, interpretable, baseline        |
| **Random Forest** | `RandomForestClassifier` | Bagging ensemble, reduces variance   |
| **Extra Trees**   | `ExtraTreesClassifier`   | Extreme randomization, fast training |

All models use default hyperparameters with `random_state=42`. The dataset is split 80/20 (train/test) with stratification.

### 4. Evaluation

The notebook reports per-model:

- Accuracy, Precision, Recall, F1-score
- Confusion matrix
- Classification report

### 5. Model Export

Models are saved as `.joblib` files into the `models/` subdirectory. These are loaded at runtime by `App/UrlThreadDetection/url_analyzer_production.py`.

---

## How Models Are Used at Runtime

The Django app (`App/UrlThreadDetection/`) loads models on first request:

1. `url_analyzer_production.py` → `URLThreatAnalyzer._load_models()` reads all 3 `.joblib` files from `Services/URL threat scanning/models/`
2. On each request, `extract_advanced_features(url)` produces the same 35+ feature vector
3. Each model predicts independently → majority vote determines the final label
4. `views.py` combines the ML prediction with domain, structure, and reputation scores using weighted averaging:

```
risk = ml_score × 0.40 + domain_score × 0.20 + structure_score × 0.20 + reputation_score × 0.20
```

---

## 6-Step Analysis Pipeline (in views.py)

| Step | Name                  | Weight            |
| ---- | --------------------- | ----------------- |
| 1    | URL Normalization     | — (preprocessing) |
| 2    | Blocklist & IP Check  | — (pre-filter)    |
| 3    | Domain Analysis       | 20%               |
| 4    | URL Structure         | 20%               |
| 5    | Reputation Heuristics | 20%               |
| 6    | ML Classification     | 40%               |

---

## Retraining

To retrain with updated data:

```bash
cd "Services/URL threat scanning"
jupyter notebook Main.ipynb
```

Run all cells. The notebook will:

1. Download fresh URL lists from Cisco Umbrella, OpenPhish, and PhishTank
2. Extract features from all URLs
3. Train all 3 models
4. Save updated `.joblib` files to `models/`
5. Print evaluation metrics

No Django restart required — models are lazy-loaded and the path is read at import time.

---

## Dependencies

```
scikit-learn
joblib
pandas
numpy
tld
requests
matplotlib   # notebook visualizations only
seaborn      # notebook visualizations only
```
