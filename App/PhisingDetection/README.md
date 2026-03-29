# Phishing Detection — CyberX Module

Real-time phishing URL classifier powered by a PyTorch deep-learning MLP trained on 11,431 URLs with 87 engineered features. Achieves ~95% accuracy.

---

## Architecture

```
Input (URL string)
        │
        ▼
Trusted-Domain Whitelist check
(google.com, github.com, …)
        │
        ▼
Feature Extractor (feature_extractor.py)
  ├── URL structure features      (12)
  ├── Domain intelligence         (15)
  ├── HTML content features       (17)
  ├── JavaScript analysis         (10)
  ├── Meta / anchor tags          (11)
  ├── Brand / phishing hints      (12)
  └── Statistical / misc          (10)
                                Total: 87 features
        │
        ▼
StandardScaler normalization
        │
        ▼
PyTorch MLP (phishing_model_full.pth)
  Input(87) → FC(256) → BN → ReLU → Dropout(0.3)
            → FC(128) → BN → ReLU → Dropout(0.2)
            → FC(64)  → ReLU
            → FC(1)   → Sigmoid
        │
        ▼
Result: Legitimate | Phishing  (+ confidence %)
```

---

## Dataset

| Attribute  | Value                   |
| ---------- | ----------------------- |
| Source     | Kaggle Phishing Dataset |
| Total URLs | 11,431                  |
| Legitimate | 5,715 (50%)             |
| Phishing   | 5,716 (50%)             |
| Features   | 87 (pre-computed)       |

---

## Feature Groups (87 total)

| Group                  | Count | Examples                                                                 |
| ---------------------- | ----- | ------------------------------------------------------------------------ |
| URL structure          | 12    | `length_url`, `nb_dots`, `nb_hyphens`, `nb_at`                           |
| Domain intelligence    | 15    | `nb_subdomains`, `prefix_suffix`, `shortening_service`, `suspicious_tld` |
| HTML content           | 17    | `nb_hyperlinks`, `ratio_intHyperlinks`, `login_form`                     |
| JavaScript             | 10    | `right_clic`, `empty_title`, `domain_with_copyright`                     |
| Meta / anchor tags     | 11    | `ratio_extMedias`, `safe_anchor`, `links_in_tags`                        |
| Brand / phishing hints | 12    | `domain_in_brand`, `phish_hints`, `brand_in_subdomain`                   |
| Statistical / misc     | 10    | `page_rank`, `google_index`, `statistical_report`                        |

---

## Key Files

| File                   | Purpose                                                                   |
| ---------------------- | ------------------------------------------------------------------------- |
| `views.py`             | Django view — feature extraction orchestration and prediction             |
| `feature_extractor.py` | Computes all 87 features from a raw URL string                            |
| `models.py`            | `PhishingDetectionResult` DB model                                        |
| `urls.py`              | Route: `/phishingdetection/`                                              |
| `models/`              | `phishing_model_full.pth`, `phishing_scaler.joblib`, `feature_names.json` |

---

## API

### `POST /phishingdetection/`

| Field | Type   | Required | Description    |
| ----- | ------ | -------- | -------------- |
| `url` | string | Yes      | URL to analyze |

**Response (JSON)**

```json
{
  "url": "http://example.com",
  "prediction": "Phishing",
  "confidence": 94.7,
  "risk_level": "High",
  "top_features": [
    { "feature": "nb_subdomains", "value": 4, "importance": "high" }
  ]
}
```

---

## Setup

### 1. Install Dependencies

```bash
pip install torch torchvision requests beautifulsoup4 tldextract joblib
```

### 2. Train the Model _(optional — pre-trained weights included)_

Open `Services/Phishing-detection/Model.ipynb` and run all cells. Artifacts are saved to `App/PhisingDetection/models/`.

### 3. Run Server

```bash
cd App
python manage.py runserver
```
