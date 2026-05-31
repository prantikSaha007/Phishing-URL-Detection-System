# PhishGuard 🛡

**ML-Powered Phishing URL Detection System with Cyber Threat Intelligence Integration**

> Real-time phishing protection via Chrome extension + FastAPI backend + React analyst dashboard.

---

## Project Structure

```
phishguard/
├── ml/
│   ├── features.py        # URL feature extraction (30+ features)
│   └── train.py           # Training pipeline (XGBoost / GBM)
├── backend/
│   ├── main.py            # FastAPI application
│   ├── cti.py             # VirusTotal + URLhaus integrations
│   ├── forensics.py       # WHOIS / DNS / typosquatting
│   ├── obfuscation.py     # URL decoding (percent, data URI, IP variants)
│   └── requirements.txt
├── dashboard/
│   └── src/
│       ├── App.jsx
│       ├── pages/         # Dashboard, ScanHistory, ScanDetail
│       ├── components/    # Navbar
│       └── utils/api.js
├── extension/
│   ├── manifest.json      # MV3 Chrome extension
│   ├── background.js      # Service worker
│   ├── content.js         # Warning overlay
│   ├── popup.html
│   └── popup.js
└── docs/
    └── REPORT.md          # Architecture & methods report
```

---

## Quick Start

### 1. Train the Model

```bash
cd ml
pip install scikit-learn xgboost pandas numpy

# Option A – separate CSVs
python train.py --phishing ../data/phishing.csv --benign ../data/benign.csv --output ../backend/artifacts

# Option B – single dataset (ISCX-URL-2016)
python train.py --dataset ../data/ISCX_URL_2016.csv --label label --url-col url --output ../backend/artifacts
```

**Recommended datasets:**
- Phishing: https://www.phishtank.com/developer_info.php (download verified_online.csv)
- Benign: https://tranco-list.eu/ (top 1M domains)
- Benchmark: ISCX-URL-2016 on Kaggle

### 2. Configure API Keys (optional but recommended)

```bash
export VT_API_KEY="your_virustotal_api_key"
```

Get a free VirusTotal key at https://www.virustotal.com/gui/join-us

### 3. Start the Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

API docs: http://localhost:8000/docs

### 4. Start the Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Dashboard: http://localhost:5173

### 5. Load the Chrome Extension

1. Open Chrome → `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` folder
4. PhishGuard icon appears in the toolbar

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/scan` | POST | `{"url": "https://..."}` → full scan result |
| `/scans` | GET | `?verdict=phishing&limit=50` |
| `/scans/{id}` | GET | Single scan |
| `/scans/{id}/report` | GET | IoC report JSON |
| `/stats` | GET | Aggregate counts |

---

## Model Performance Targets

| Metric | Target |
|---|---|
| Accuracy | ≥ 95% |
| F1 Score | ≥ 0.95 |
| ROC-AUC | ≥ 0.98 |
| Inference latency | < 5ms (ML only) |
| End-to-end API | < 500ms |

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `VT_API_KEY` | `""` | VirusTotal API key |
| `ARTIFACTS_DIR` | `artifacts` | Path to `model.pkl` + `scaler.pkl` |
| `VITE_API_BASE` | `http://localhost:8000` | Backend URL for dashboard |
