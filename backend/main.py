"""
PhishGuard – FastAPI Backend
Orchestrates ML inference + live CTI lookups.

Run:
    uvicorn main:app --reload --port 8000
"""

import asyncio
import hashlib
import json
import os
import pickle
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

if load_dotenv:
    load_dotenv(Path(__file__).with_name(".env"))

# ── Local imports ──────────────────────────────────────────────────────────────
import sys
sys.path.append(str(Path(__file__).parent.parent / "ml"))
from features import extract_features  # noqa: E402

from cti import CTIOrchestrator          # noqa: E402
from forensics import DNSWHOISForensics  # noqa: E402
from obfuscation import decode_url       # noqa: E402

from download_model import download_if_missing
download_if_missing()
# ─────────────────────────────────────────────────────────────────────────────
# App bootstrap
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="PhishGuard API",
    version="1.0.0",
    description="ML-Powered Phishing URL Detection with Cyber Threat Intelligence",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
    "http://localhost:5173",
    "https://phishing-url-detection-system-psi.vercel.app/",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory scan store (replace with DB in production) ──────────────────────
scan_store: Dict[str, Dict] = {}

# ── Load ML artefacts ─────────────────────────────────────────────────────────
ARTIFACTS_DIR = Path(os.getenv("ARTIFACTS_DIR", "artifacts"))
_model  = None
_scaler = None

def _load_model():
    global _model, _scaler
    model_path  = ARTIFACTS_DIR / "model.pkl"
    scaler_path = ARTIFACTS_DIR / "scaler.pkl"
    if model_path.exists() and scaler_path.exists():
        with open(model_path,  "rb") as f: _model  = pickle.load(f)
        with open(scaler_path, "rb") as f: _scaler = pickle.load(f)
        print("ML model loaded")
    else:
        print("No trained model found; ML scoring disabled")

_load_model()

cti       = CTIOrchestrator()
forensics = DNSWHOISForensics()

# ─────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ─────────────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: str
    source: str = "api"   # api | extension | dashboard

class ThreatScore(BaseModel):
    score: float           # 0.0 – 1.0
    label: str             # benign | suspicious | phishing
    confidence: float

class ScanResult(BaseModel):
    scan_id:     str
    url:         str
    decoded_url: str
    timestamp:   str
    duration_ms: float
    threat:      ThreatScore
    ml_features: Dict[str, float]
    cti:         Dict[str, Any]
    forensics:   Dict[str, Any]
    risk_factors: List[str]
    ioc_report:  Dict[str, Any]

# ─────────────────────────────────────────────────────────────────────────────
# Core scoring logic
# ─────────────────────────────────────────────────────────────────────────────

def _ml_score(features: Dict[str, float]) -> float:
    """Returns probability [0,1] that URL is phishing."""
    if _model is None or _scaler is None:
        return 0.5  # neutral fallback
    try:
        x = np.array([list(features.values())], dtype=np.float32)
        x_scaled = _scaler.transform(x)
        return float(_model.predict_proba(x_scaled)[0][1])
    except Exception as e:
        print(f"ML scoring error: {e}")
        return 0.5


def _aggregate_score(ml: float, cti_data: dict, forensics_data: dict) -> tuple[float, list[str]]:
    """
    Combine ML probability with CTI signals into a final risk score.
    Returns (score 0-1, list of risk factor strings).
    """
    score = ml
    factors = []

    if ml >= 0.7:
        factors.append(f"ML classifier: {ml:.0%} phishing probability")

    # CTI boosts
    if cti_data.get("virustotal", {}).get("malicious", 0) > 2:
        score = min(score + 0.3, 1.0)
        n = cti_data["virustotal"]["malicious"]
        factors.append(f"VirusTotal: {n} engines flagged as malicious")

    if cti_data.get("urlhaus", {}).get("found"):
        score = min(score + 0.4, 1.0)
        factors.append("URLhaus: URL found in live malware database")

    if cti_data.get("phishtank", {}).get("in_database"):
        score = min(score + 0.5, 1.0)
        factors.append("PhishTank: Confirmed phishing URL")

    # Forensics signals
    if forensics_data.get("domain_age_days") is not None:
        age = forensics_data["domain_age_days"]
        if age < 30:
            score = min(score + 0.15, 1.0)
            factors.append(f"Newly registered domain ({age} days old)")

    if forensics_data.get("typosquat_target"):
        score = min(score + 0.2, 1.0)
        factors.append(f"Typosquatting detected → '{forensics_data['typosquat_target']}'")

    if not forensics_data.get("dns_resolves", True):
        score = min(score + 0.1, 1.0)
        factors.append("Domain does not resolve in DNS")

    return round(score, 4), factors


def _label(score: float) -> str:
    if score >= 0.65: return "phishing"
    if score >= 0.40: return "suspicious"
    return "benign"


def _build_ioc_report(url: str, decoded: str, features: dict,
                       cti_data: dict, forensics_data: dict,
                       score: float, factors: list) -> dict:
    return {
        "report_id":     str(uuid.uuid4()),
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "ioc": {
            "type":  "url",
            "value": url,
            "decoded": decoded,
            "sha256": hashlib.sha256(url.encode()).hexdigest(),
            "md5":    hashlib.md5(url.encode()).hexdigest(),
        },
        "risk_score":   score,
        "verdict":      _label(score),
        "risk_factors": factors,
        "infrastructure": {
            "domain":      forensics_data.get("domain"),
            "registrar":   forensics_data.get("registrar"),
            "creation_date": str(forensics_data.get("creation_date", "")),
            "country":     forensics_data.get("country"),
            "ip_addresses": forensics_data.get("ip_addresses", []),
            "mx_records":  forensics_data.get("mx_records", []),
        },
        "threat_intel": cti_data,
    }

# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "model_loaded": _model is not None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/")
async def root():
    return {
        "name": "PhishGuard API",
        "status": "running",
        "dashboard_url": "http://localhost:5173",
        "api_docs": "http://localhost:8000/docs",
        "health": "http://localhost:8000/health",
        "model_loaded": _model is not None,
    }


@app.post("/scan", response_model=ScanResult)
async def scan(req: ScanRequest):
    t0 = time.perf_counter()
    scan_id = str(uuid.uuid4())

    raw_url = req.url.strip()

    # 1. Decode obfuscation
    decoded_url = decode_url(raw_url)

    # 2. Extract ML features
    features = extract_features(decoded_url)

    # 3. ML score
    ml_prob = _ml_score(features)

    # 4. CTI + forensics in parallel
    cti_data, forensics_data = await asyncio.gather(
        cti.query(decoded_url),
        forensics.analyze(decoded_url),
    )

    # 5. Aggregate
    final_score, risk_factors = _aggregate_score(ml_prob, cti_data, forensics_data)

    duration_ms = (time.perf_counter() - t0) * 1000

    result = {
        "scan_id":     scan_id,
        "url":         raw_url,
        "decoded_url": decoded_url,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "duration_ms": round(duration_ms, 2),
        "threat": {
            "score":      final_score,
            "label":      _label(final_score),
            "confidence": round(abs(final_score - 0.5) * 2, 4),
        },
        "ml_features": features,
        "cti":         cti_data,
        "forensics":   forensics_data,
        "risk_factors": risk_factors,
        "ioc_report":  _build_ioc_report(
            raw_url, decoded_url, features, cti_data, forensics_data,
            final_score, risk_factors),
    }

    scan_store[scan_id] = result
    return result


@app.get("/scans", response_model=List[Dict])
async def list_scans(
    limit: int = Query(50, ge=1, le=500),
    verdict: Optional[str] = Query(None, pattern="^(benign|suspicious|phishing)$"),
):
    items = list(scan_store.values())
    if verdict:
        items = [i for i in items if i["threat"]["label"] == verdict]
    items.sort(key=lambda x: x["timestamp"], reverse=True)
    return items[:limit]


@app.get("/scans/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str):
    if scan_id not in scan_store:
        raise HTTPException(404, "Scan not found")
    return scan_store[scan_id]


@app.get("/scans/{scan_id}/report")
async def download_report(scan_id: str):
    if scan_id not in scan_store:
        raise HTTPException(404, "Scan not found")
    return scan_store[scan_id]["ioc_report"]


@app.get("/stats")
async def stats():
    items = list(scan_store.values())
    if not items:
        return {"total": 0}
    verdicts = [i["threat"]["label"] for i in items]
    return {
        "total":       len(items),
        "phishing":    verdicts.count("phishing"),
        "suspicious":  verdicts.count("suspicious"),
        "benign":      verdicts.count("benign"),
        "avg_score":   round(sum(i["threat"]["score"] for i in items) / len(items), 4),
        "avg_duration_ms": round(sum(i["duration_ms"] for i in items) / len(items), 2),
    }


@app.delete("/scans")
async def clear_scans():
    scan_store.clear()
    return {"cleared": True}
