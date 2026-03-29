# Email Validation — CyberX Module

Multi-layer email verification system that combines syntax checking, DNS lookups, disposable-domain detection, and email-authentication record analysis to produce a weighted risk score.

---

## Architecture — 9-Layer Pipeline

```
Input (email string)
        │
        ▼
Layer 1 ── Regex Format Check         (RFC 5322 pattern, consecutive-dot / start-end rules)
        │
        ▼
Layer 2 ── email-validator Library    (full RFC + internationalization + normalization)
        │
        ▼
Layer 3 ── Disposable-Domain Blocklist (5,100+ domains; parent-domain matching)
        │
        ▼
Layer 4 ── Temp-Email Heuristics      (14 regex patterns · keywords · suspicious TLDs)
        │
        ▼
Layer 5 ── Domain Age (WHOIS)         (<30 d = high risk … 365 d+ = safe; 7-day cache)
        │
        ▼
Layer 6 ── SPF Record                 (strict -all / softfail ~all / neutral / permissive)
        │
        ▼
Layer 7 ── DKIM Signature             (11 common selectors probed; public-key check)
        │
        ▼
Layer 8 ── DMARC Policy               (_dmarc.<domain> TXT; reject / quarantine / none)
        │
        ▼
Layer 9 ── MX / DNS Deliverability    (MX priority sort; A-record fallback per RFC 5321)
        │
        ▼
Weighted Risk Score (0 – 100)
```

---

## Risk-Scoring Weights

| Component                  | Weight |
| -------------------------- | -----: |
| Blocklist / temp detection |    30% |
| Domain age (WHOIS)         |    15% |
| SPF record                 |    15% |
| DKIM signature             |    10% |
| DMARC policy               |    10% |
| MX deliverability          |    10% |
| Heuristics                 |    10% |

### Risk Levels

| Score  | Level    |
| ------ | -------- |
| 0–19   | Safe     |
| 20–39  | Low      |
| 40–59  | Medium   |
| 60–79  | High     |
| 80–100 | Critical |

---

## Key Files

| File                     | Purpose                                                         |
| ------------------------ | --------------------------------------------------------------- |
| `views.py`               | Django view — drives the 9-layer pipeline and returns JSON      |
| `models.py`              | `EmailValidationLog`, `DomainCache`, `BehavioralFlag` DB models |
| `disposable_domains.txt` | 5,100+ known disposable/temporary email domains                 |
| `urls.py`                | Route: `/emailvalidation/`                                      |

---

## Behavioral Monitoring

- **Rate limiting**: 10-minute sliding window per IP; flags after 20 queries.
- **Bulk temp-email detection**: ≥ 5 disposable emails from same IP within 1 hour.
- **Domain abuse**: single domain queried > 50 times total.
- All flags stored in `BehavioralFlag` with severity levels.

---

## API

### `POST /emailvalidation/`

| Field   | Type   | Required | Description               |
| ------- | ------ | -------- | ------------------------- |
| `email` | string | Yes      | Email address to validate |

**Response (JSON)**

```json
{
  "valid": true,
  "deliverable": true,
  "is_temporary": false,
  "risk_score": 12,
  "risk_level": "Safe",
  "spf": "strict",
  "dkim": true,
  "dmarc": "reject",
  "provider": "Gmail",
  "recommendations": []
}
```

---

## Setup

```bash
pip install dnspython python-whois email-validator
cd App
python manage.py migrate EmailValidation
python manage.py runserver
```
