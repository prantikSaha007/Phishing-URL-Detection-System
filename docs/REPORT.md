# PhishGuard – Architecture & Methods Report

## 1. System Overview

PhishGuard is a real-time phishing URL detection system that combines statistical machine learning with active Cyber Threat Intelligence (CTI). The system is designed to mirror Security Operations Center (SOC) workflows and is deployable as a Chrome browser extension backed by a FastAPI service.

---

## 2. Architecture

```
Browser (Chrome Extension)
        │
        │  POST /scan
        ▼
┌─────────────────────────────────────────────────┐
│               FastAPI Backend                   │
│                                                 │
│  ┌──────────────┐  ┌──────────────────────────┐ │
│  │ Obfuscation  │  │   Feature Extraction      │ │
│  │   Decoder    │  │   (30+ statistical feats) │ │
│  └──────┬───────┘  └────────────┬─────────────┘ │
│         │                       │               │
│         └──────────┬────────────┘               │
│                    ▼                             │
│           ┌────────────────┐                    │
│           │  XGBoost Model │  (P(phishing))     │
│           └───────┬────────┘                    │
│                   │                             │
│     ┌─────────────┼─────────────┐               │
│     ▼             ▼             ▼               │
│  VirusTotal    URLhaus     WHOIS/DNS             │
│  (async)       (async)     Forensics             │
│     │             │             │               │
│     └─────────────┴─────────────┘               │
│                   │                             │
│           ┌───────▼───────┐                     │
│           │ Score Fusion  │                     │
│           │ + IoC Report  │                     │
│           └───────────────┘                     │
└─────────────────────────────────────────────────┘
        │
        ▼
React Analyst Dashboard  (scan history, charts, export)
```

---

## 3. Machine Learning Pipeline

### 3.1 Feature Engineering (30+ features)

Features are extracted purely from the URL string — no network I/O during inference:

| Category | Features |
|---|---|
| **Length** | URL length, domain length, path length, query length, subdomain length |
| **Character counts** | Dots, hyphens, slashes, at-signs, equals, ampersands, percent signs, digits |
| **Statistical** | Shannon entropy of URL / domain / path, digit ratio in domain |
| **Boolean flags** | IP address in hostname, HTTPS, hex-encoding, URL shortener, suspicious TLD |
| **Linguistic** | Count of suspicious keywords (login, verify, banking…), brand names in subdomain/path |
| **Structural** | Subdomain depth, redirect parameters, punycode, data URIs |

### 3.2 Model

**Algorithm**: XGBoost (`XGBClassifier`) — chosen for its strong performance on tabular URL features, resistance to class imbalance (via `scale_pos_weight`), and fast inference (<5ms per URL).

**Fallback**: `GradientBoostingClassifier` from scikit-learn if XGBoost is unavailable.

**Training procedure**:
1. Load balanced dataset (PhishTank phishing + Tranco benign / ISCX-URL-2016)
2. Feature extraction → `StandardScaler` normalization
3. 80/20 stratified train/test split
4. 5-fold stratified cross-validation
5. Evaluation: accuracy, precision, recall, F1, ROC-AUC, confusion matrix

**Target performance**: ≥95% accuracy on balanced dataset, <500ms end-to-end API response.

---

## 4. Obfuscation Decoding

The `obfuscation.py` module normalizes URLs before feature extraction and CTI lookup:

- **Percent-encoding**: Single and double `%XX` decoding
- **Data URIs**: Base64-encoded `data:text/html` payloads decoded; inner redirect URLs extracted
- **Redirect wrappers**: Extracts `?url=`, `?redirect=`, `?next=`, `?goto=` etc.
- **Unicode/Punycode**: IDN hostname normalization (`xn--...` → ASCII)
- **IP variants**: Dword integers (e.g., `3232235521` → `192.168.0.1`), hex IPs (`0xC0A80001`), octal IPs

---

## 5. Cyber Threat Intelligence (CTI)

All CTI lookups are executed **asynchronously in parallel** (`asyncio.gather`) to keep total API latency below 500ms.

| Source | Method | Signal |
|---|---|---|
| **VirusTotal** | URL reputation via `/api/v3/urls/{id}` | Malicious engine count |
| **URLhaus** | POST to `urlhaus-api.abuse.ch/v1/url/` | Known malware distribution |

CTI signals are fused with the ML score through a **weighted additive model**:
- URLhaus hit: +0.40
- PhishTank confirmed: +0.50
- VirusTotal ≥3 engines: +0.30
- Domain age <30 days: +0.15
- Typosquat detected: +0.20

---

## 6. DNS / WHOIS Forensics

Passive forensic analysis (`forensics.py`) runs concurrently with CTI:

- **WHOIS**: Registrar, creation date, expiration date, country (`python-whois`)
- **DNS**: A records (socket), MX records, NS records (`dnspython`)
- **Domain age**: Derived from WHOIS creation date — newly registered domains (<30 days) are a strong phishing signal
- **Typosquatting**: Levenshtein distance ≤2 against 28 major brands; also detects homoglyph substitution and brand embedding

---

## 7. Score Fusion & Verdict

```
final_score = clip(ml_probability + Σ cti_boosts, 0, 1)

Verdict thresholds:
  ≥ 0.65  →  phishing   (red)
  ≥ 0.40  →  suspicious (amber)
  < 0.40  →  benign     (green)
```

---

## 8. Backend API (FastAPI)

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Liveness check, model status |
| `/scan` | POST | Full URL scan pipeline |
| `/scans` | GET | List scans (filterable by verdict) |
| `/scans/{id}` | GET | Single scan result |
| `/scans/{id}/report` | GET | IoC report JSON |
| `/stats` | GET | Aggregate statistics |

Scan results are stored in-memory (replace with PostgreSQL/Redis for production). Each result includes the full ML feature vector, CTI data, forensics, risk factor list, and a structured IoC report with SHA-256/MD5 hashes.

---

## 9. Chrome Extension

- **Manifest V3** service worker (`background.js`)
- Hooks `webNavigation.onCommitted` for automatic scanning of every navigation
- 10-minute in-memory cache to avoid re-scanning the same URL
- Desktop notification + full-page warning overlay for high-confidence phishing (score ≥ 0.8)
- 200-scan local history stored via `chrome.storage.local`
- Popup with live verdict, score bar, risk factors, and session stats

---

## 10. Analyst Dashboard (React)

- **Dashboard**: URL scan input, live verdict card, donut chart (risk distribution), area chart (threat scores over time), recent scans table
- **Scan History**: Filterable/searchable table, CSV export, IoC JSON bulk export
- **Scan Detail**: Full forensics panel, CTI results, radar chart of ML feature profile, raw feature vector, downloadable IoC report

---

## 11. Datasets

| Dataset | Use |
|---|---|
| PhishTank | Verified phishing URLs (positive class) |
| URLhaus | Additional malicious URLs + live CTI |
| Tranco Top 1M | Legitimate domains (negative class) |
| ISCX-URL-2016 | Benchmark evaluation |

---

## 12. Tech Stack Summary

| Layer | Technology |
|---|---|
| ML | Python, scikit-learn, XGBoost, Pandas, NumPy |
| Backend | FastAPI, uvicorn, aiohttp, pydantic |
| Threat Intel | VirusTotal API v3, URLhaus API |
| Forensics | python-whois, dnspython, urllib |
| Frontend | React, Tailwind CSS, Recharts |
| Extension | JavaScript (MV3), HTML/CSS |
