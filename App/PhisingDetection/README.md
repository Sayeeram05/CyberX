# 🎣 Phishing Detection - CyberX

## Overview

CyberX Phishing Detection is an advanced real-time URL analysis system powered by PyTorch neural networks. Trained on over 11,000 URLs with 87 carefully engineered features, it provides highly accurate phishing detection with detailed explanations and recommendations.

---

## 🎯 Problem Statement

Phishing attacks remain one of the most prevalent cyber threats:

- **91%** of cyber attacks start with phishing
- **$17,700** average cost per minute of phishing attack
- **Billions** of phishing emails sent daily worldwide

Our solution provides:

1. **Deep Learning Model**: PyTorch neural network trained on real data
2. **87 Features**: Comprehensive URL and content analysis
3. **Real-time Detection**: Instant threat assessment
4. **Trusted Domain Recognition**: Zero false positives for major sites

---

## 🧠 Machine Learning Pipeline

### Data Collection

```
┌─────────────────────────────────────────────────────────────────┐
│                      Dataset Overview                            │
├─────────────────────────────────────────────────────────────────┤
│  Source: Kaggle Phishing Detection Dataset                      │
│  Total URLs: 11,431                                             │
│  Legitimate: 5,715 (50%)                                        │
│  Phishing: 5,716 (50%)                                          │
│  Features: 87 (pre-computed)                                    │
└─────────────────────────────────────────────────────────────────┘
```

### Feature Engineering (87 Features)

#### 1. URL-Based Features (12)

Features extracted directly from the URL string:

| Feature           | Description        | Phishing Indicator              |
| ----------------- | ------------------ | ------------------------------- |
| `length_url`      | Total URL length   | Very long URLs (>75 chars)      |
| `length_hostname` | Hostname length    | Long hostnames suspicious       |
| `ip`              | Uses IP address    | Direct IP = high risk           |
| `nb_dots`         | Count of dots      | Many dots = suspicious          |
| `nb_hyphens`      | Count of hyphens   | Multiple hyphens suspicious     |
| `nb_at`           | Count of @ symbols | @ in URL = credential theft     |
| `nb_qm`           | Question marks     | Complex queries suspicious      |
| `nb_and`          | Count of &         | Many parameters = suspicious    |
| `nb_eq`           | Count of =         | Multiple assignments suspicious |
| `nb_underscore`   | Underscores        | Common in phishing domains      |
| `nb_tilde`        | Tilde characters   | Often in hidden pages           |
| `nb_percent`      | Percent signs      | URL encoding = obfuscation      |

#### 2. Domain-Based Features (15)

Domain intelligence and structure analysis:

| Feature              | Description              | Phishing Indicator         |
| -------------------- | ------------------------ | -------------------------- |
| `nb_subdomains`      | Subdomain count          | Many subdomains suspicious |
| `prefix_suffix`      | Has dash separator       | paypal-secure suspicious   |
| `random_domain`      | Random-looking domain    | Random chars = generated   |
| `shortening_service` | URL shortener            | Hides true destination     |
| `punycode`           | Internationalized domain | Homograph attacks          |
| `domain_in_brand`    | Brand in domain          | Brand impersonation        |
| `brand_in_subdomain` | Brand in subdomain       | Credential theft attempt   |
| `brand_in_path`      | Brand in path            | URL impersonation          |
| `suspecious_tld`     | Suspicious TLD           | .tk, .ml, .ga are risky    |
| `statistical_report` | In known reports         | Previously reported        |
| `nb_www`             | Multiple www             | www-secure-www suspicious  |
| `ratio_digits_url`   | Digit ratio              | Many numbers suspicious    |
| `ratio_digits_host`  | Digits in host           | 123abc.com suspicious      |
| `tld_in_path`        | TLD in path              | .com in path suspicious    |
| `tld_in_subdomain`   | TLD in subdomain         | com.example.com suspicious |

#### 3. HTML Content Features (17)

Website content analysis (when page is fetched):

| Feature                | Description          | Phishing Indicator         |
| ---------------------- | -------------------- | -------------------------- |
| `nb_hyperlinks`        | Link count           | Few links suspicious       |
| `ratio_intHyperlinks`  | Internal link ratio  | Low ratio suspicious       |
| `ratio_extHyperlinks`  | External link ratio  | High external suspicious   |
| `nb_extCSS`            | External CSS count   | Loading from elsewhere     |
| `ratio_intRedirection` | Internal redirects   | Legitimate use redirects   |
| `ratio_extRedirection` | External redirects   | Redirect to evil site      |
| `ratio_intErrors`      | Internal errors      | Broken links indicate fake |
| `ratio_extErrors`      | External errors      | External broken links      |
| `login_form`           | Has login form       | Primary phishing target    |
| `external_favicon`     | External favicon     | Impersonating another site |
| `links_in_tags`        | Links in meta/script | Hidden redirects           |
| `submit_email`         | Form to email        | Direct data exfiltration   |
| `ratio_intMedia`       | Internal media       | Real sites host media      |
| `ratio_extMedia`       | External media       | Phishers hotlink media     |
| `sfh`                  | Server Form Handler  | Where form data goes       |
| `iframe`               | Uses iframes         | Can load malicious content |
| `popup_window`         | Creates popups       | Aggressive behavior        |

#### 4. Security & External Features (43)

WHOIS, DNS, and external service features:

| Feature                      | Description          | Phishing Indicator          |
| ---------------------------- | -------------------- | --------------------------- |
| `https_token`                | Uses HTTPS           | No HTTPS = risky            |
| `phish_hints`                | Phishing keywords    | Contains "secure", "verify" |
| `domain_in_title`            | Domain matches title | Mismatch suspicious         |
| `domain_with_copyright`      | Has copyright        | Legitimate indicator        |
| `whois_registered_domain`    | WHOIS registered     | Unregistered suspicious     |
| `domain_registration_length` | Registration period  | Short = suspicious          |
| `domain_age`                 | Age in days          | <30 days very suspicious    |
| `web_traffic`                | Traffic rank         | No traffic suspicious       |
| `dns_record`                 | Has DNS records      | No records = fake           |
| `google_index`               | In Google index      | Not indexed suspicious      |

### Neural Network Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    PyTorch Neural Network                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│    ┌──────────────────────────────────────────────────────┐     │
│    │            Input Layer (87 features)                 │     │
│    │                                                      │     │
│    │  URL features + Domain features + HTML features +    │     │
│    │  WHOIS features + DNS features + External features   │     │
│    └──────────────────────────────────────────────────────┘     │
│                              │                                   │
│                              ▼                                   │
│    ┌──────────────────────────────────────────────────────┐     │
│    │         Hidden Layer 1 (300 neurons)                 │     │
│    │         • Activation: ReLU                           │     │
│    │         • BatchNorm1d(300)                           │     │
│    └──────────────────────────────────────────────────────┘     │
│                              │                                   │
│                              ▼                                   │
│    ┌──────────────────────────────────────────────────────┐     │
│    │         Hidden Layer 2 (100 neurons)                 │     │
│    │         • Activation: ReLU                           │     │
│    │         • BatchNorm1d(100)                           │     │
│    │         • Dropout(p=0.1)                             │     │
│    └──────────────────────────────────────────────────────┘     │
│                              │                                   │
│                              ▼                                   │
│    ┌──────────────────────────────────────────────────────┐     │
│    │          Output Layer (1 neuron)                     │     │
│    │         • Activation: Sigmoid                        │     │
│    │         • Output: 0-1 probability                    │     │
│    │         • >0.5 = Legitimate, ≤0.5 = Phishing        │     │
│    └──────────────────────────────────────────────────────┘     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Training Process

```python
# Model Definition
class PhishingModel(nn.Module):
    def __init__(self, n_input_dim=87):
        super().__init__()
        self.layer_1 = nn.Linear(n_input_dim, 300)
        self.layer_2 = nn.Linear(300, 100)
        self.layer_out = nn.Linear(100, 1)

        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()
        self.dropout = nn.Dropout(p=0.1)
        self.batchnorm1 = nn.BatchNorm1d(300)
        self.batchnorm2 = nn.BatchNorm1d(100)

# Training Configuration
optimizer = Adam(model.parameters(), lr=0.001)
criterion = BCELoss()
epochs = 100  # With early stopping
batch_size = 64

# Feature Scaling
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# Save artifacts
torch.save(model.state_dict(), 'phishing_model.pth')
joblib.dump(scaler, 'phishing_scaler.joblib')
```

### Model Performance

| Metric             | Value         |
| ------------------ | ------------- |
| **Accuracy**       | ~95%          |
| **Precision**      | ~94%          |
| **Recall**         | ~96%          |
| **F1-Score**       | ~95%          |
| **Training Time**  | ~5 minutes    |
| **Inference Time** | <10ms per URL |

---

## 🏗️ System Architecture

### Analysis Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                      User Input (URL)                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  URL Normalization                               │
│  • Add https:// if missing                                      │
│  • Parse domain, path, query                                    │
│  • Check trusted domain list                                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              Feature Extraction (87 features)                    │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐          │
│  │ URL Parser  │  │ HTML Fetcher │  │ WHOIS Lookup   │          │
│  │ (tldextract)│  │ (requests)   │  │ (python-whois) │          │
│  └─────────────┘  └──────────────┘  └────────────────┘          │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐          │
│  │ DNS Query   │  │ BeautifulSoup│  │ Math/Stats     │          │
│  │ (dnspython) │  │ (HTML parse) │  │ Calculations   │          │
│  └─────────────┘  └──────────────┘  └────────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                Feature Normalization                             │
│           (MinMaxScaler - trained on dataset)                    │
│                                                                  │
│  CRITICAL: Must use the same scaler from training!              │
│  scaler.transform() NOT fit_transform() for new data            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              PyTorch Model Inference                             │
│                                                                  │
│  feature_tensor = torch.from_numpy(features).float()            │
│  with torch.no_grad():                                          │
│      probability = model(feature_tensor).item()                 │
│                                                                  │
│  is_legitimate = probability > 0.5                              │
│  confidence = probability if legitimate else (1 - probability)  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Result Generation                               │
│                                                                  │
│  • is_phishing: Boolean result                                  │
│  • confidence: 0-100% confidence score                          │
│  • risk_score: 0-100 risk assessment                           │
│  • risk_factors: List of specific concerns                      │
│  • security_indicators: Positive signals                        │
│  • recommendation: Security advice                              │
└─────────────────────────────────────────────────────────────────┘
```

### File Structure

```
App/PhisingDetection/
├── __init__.py
├── admin.py
├── apps.py
├── models.py
├── urls.py                    # URL routing
├── views.py                   # Main view logic (605 lines)
├── feature_extractor.py       # 87-feature extraction engine
├── tests.py
├── README.md                  # This documentation
├── migrations/
│   └── __init__.py
└── models/
    ├── phishing_model.pth     # PyTorch model weights
    ├── phishing_scaler.joblib # MinMaxScaler (trained)
    └── feature_names.json     # Feature order reference

Services/Phishing-detection/
├── Model.ipynb                # Training notebook
├── Dataset/
│   └── dataset_phishing.csv   # Training data
├── phishing_model.pth         # Original model
├── phishing_scaler.joblib     # Original scaler
└── feature_names.json         # Feature names
```

---

## 🌐 API Reference

### Web Interface

**URL**: `/phishingdetection/`

**Method**: GET (display form), POST (analyze URL)

### REST API

**Endpoint**: `/phishingdetection/api/analyze/`

**Method**: POST

**Request**:

```json
{
  "url": "https://example.com"
}
```

**Response**:

```json
{
  "success": true,
  "url": "https://example.com",
  "domain": "example.com",
  "is_phishing": false,
  "is_trusted": false,
  "confidence": 89.5,
  "risk_score": 10,
  "risk_factors": [],
  "security_indicators": [
    "HTTPS encryption enabled",
    "Valid DNS record found",
    "Domain is registered",
    "Established domain (9125 days old)"
  ],
  "processing_time_ms": 245.67,
  "model_used": true
}
```

---

## 📊 Detection Examples

### Safe URL (Trusted Domain)

```
URL: https://commons.wikimedia.org/wiki/Main_Page
├── Status: ✅ URL APPEARS SAFE
├── Trusted Domain: Yes (Wikimedia Foundation)
├── Confidence: 95.0%
├── Risk Score: 0/100
├── Security Indicators:
│   ├── ✓ Recognized trusted domain
│   ├── ✓ HTTPS encryption enabled
│   ├── ✓ Valid DNS record found
│   └── ✓ Established domain
└── Recommendation: Safe for browsing
```

### Phishing URL

```
URL: http://secure-paypa1-login.xyz/verify
├── Status: 🔴 HIGH RISK - LIKELY PHISHING
├── Confidence: 94.2%
├── Risk Score: 85/100
├── Risk Factors:
│   ├── ⚠ URL appears to impersonate known brand
│   ├── ⚠ Suspicious top-level domain detected
│   ├── ⚠ Very new domain (only 5 days old)
│   ├── ⚠ Connection is not secured with HTTPS
│   └── ⚠ Phishing keywords detected (3 found)
└── Recommendation: Do NOT visit this URL
```

### Suspicious URL

```
URL: http://192.168.1.1/admin/login.php
├── Status: ⚠️ POTENTIAL RISK DETECTED
├── Confidence: 72.1%
├── Risk Score: 45/100
├── Risk Factors:
│   ├── ⚠ URL uses IP address instead of domain
│   └── ⚠ Connection is not secured with HTTPS
├── Security Indicators:
│   └── ✓ Contains login form (neutral)
└── Recommendation: Exercise caution
```

---

## 🔒 Trusted Domain System

### Whitelist Categories

The system maintains a comprehensive whitelist of trusted domains:

```python
TRUSTED_DOMAINS = {
    # Tech Giants
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',

    # Wikimedia Foundation
    'wikipedia.org', 'wikimedia.org', 'wiktionary.org',
    'wikibooks.org', 'wikisource.org', 'mediawiki.org',

    # Government/Education (TLD-based)
    'gov', 'edu', 'mil',

    # Major Services
    'youtube.com', 'netflix.com', 'spotify.com', 'reddit.com',
    'dropbox.com', 'slack.com', 'zoom.us', 'adobe.com',

    # Cloud Providers
    'aws.amazon.com', 'azure.microsoft.com', 'cloud.google.com',

    # News & Media
    'bbc.com', 'cnn.com', 'nytimes.com', 'reuters.com',
}
```

### Subdomain Recognition

The system also recognizes subdomains of trusted domains:

- `mail.google.com` → Trusted (subdomain of google.com)
- `docs.microsoft.com` → Trusted (subdomain of microsoft.com)
- `en.wikipedia.org` → Trusted (subdomain of wikipedia.org)

---

## ⚙️ Configuration

### Dependencies

```txt
torch>=2.0.0
scikit-learn>=1.0.0
tldextract>=3.0.0
beautifulsoup4>=4.11.0
python-whois>=0.8.0
requests>=2.28.0
joblib>=1.3.0
dnspython>=2.3.0
numpy>=1.23.0
```

### Django Settings

```python
INSTALLED_APPS = [
    ...
    'PhisingDetection',
]
```

### URL Configuration

```python
# CyberX/urls.py
urlpatterns = [
    path('phishingdetection/', include('PhisingDetection.urls')),
]
```

---

## 🧪 Testing

### Test Legitimate URLs

```python
legitimate_urls = [
    "https://www.google.com",
    "https://commons.wikimedia.org/wiki/Main_Page",
    "https://github.com",
    "https://www.microsoft.com/en-us/",
]
# Expected: All should return is_phishing=False
```

### Test Phishing URLs

```python
phishing_urls = [
    "http://secure-paypa1.xyz/login",
    "http://192.168.1.1/login.php",
    "http://bit.ly/suspicious-link",
]
# Expected: Should return is_phishing=True or high risk_score
```

---

## 📚 References

- [Phishing Detection Dataset](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset)
- [PyTorch Documentation](https://pytorch.org/docs/)
- [WHOIS Protocol RFC 3912](https://datatracker.ietf.org/doc/html/rfc3912)
- [URL Structure RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986)

---

**CyberX Phishing Detection** - AI-powered protection against phishing attacks.
