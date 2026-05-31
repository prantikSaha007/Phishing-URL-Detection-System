"""
PhishGuard – ML Training Pipeline
Trains an XGBoost classifier on balanced phishing/benign URL data.
Outputs: model.pkl, scaler.pkl, metrics.json

Usage:
    python train.py --phishing data/phishing.csv --benign data/benign.csv
    python train.py --dataset data/ISCX_URL_2016.csv --label label_col
"""

import argparse
import json
import pickle
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False
    warnings.warn("xgboost not installed; falling back to GradientBoostingClassifier")

from features import extract_features, FEATURE_NAMES

# ─────────────────────────────────────────────────────────────
# Data loading helpers
# ─────────────────────────────────────────────────────────────

def load_urls_from_csv(path: str, url_col: str = "url", label_col: str | None = None,
                        label_value: int | None = None) -> pd.DataFrame:
    df = pd.read_csv(path)
    if url_col not in df.columns:
        # try first column
        url_col = df.columns[0]
    result = pd.DataFrame({"url": df[url_col].astype(str)})
    if label_col and label_col in df.columns:
        result["label"] = normalize_labels(df[label_col])
    elif label_value is not None:
        result["label"] = label_value
    return result


def normalize_labels(labels: pd.Series) -> pd.Series:
    """Convert common text/numeric URL labels into 0=benign, 1=phishing."""
    if pd.api.types.is_numeric_dtype(labels):
        return labels.astype(int)

    mapping = {
        "0": 0,
        "benign": 0,
        "safe": 0,
        "legitimate": 0,
        "legit": 0,
        "good": 0,
        "normal": 0,
        "1": 1,
        "phishing": 1,
        "phish": 1,
        "malicious": 1,
        "malware": 1,
        "bad": 1,
    }
    normalized = labels.astype(str).str.strip().str.lower().map(mapping)
    if normalized.isna().any():
        unknown = sorted(labels[normalized.isna()].astype(str).unique().tolist())
        raise ValueError(f"Unknown label values: {unknown}. Expected benign/safe/0 or phishing/malicious/1.")
    return normalized.astype(int)


def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for url in df["url"]:
        try:
            rows.append(extract_features(url))
        except Exception:
            rows.append({k: 0.0 for k in FEATURE_NAMES})
    return pd.DataFrame(rows, columns=FEATURE_NAMES).fillna(0)


def balance_classes(df: pd.DataFrame, max_per_class: int | None = None) -> pd.DataFrame:
    counts = df["label"].value_counts()
    if len(counts) < 2:
        raise ValueError("Training requires at least two labels: benign/safe and phishing/malicious.")

    n = int(counts.min())
    if max_per_class is not None:
        n = min(n, max_per_class)

    parts = [
        group.sample(n=n, random_state=42)
        for _, group in df.groupby("label", sort=False)
    ]
    return pd.concat(parts, ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)


# ─────────────────────────────────────────────────────────────
# Model factory
# ─────────────────────────────────────────────────────────────

def build_model():
    if HAS_XGB:
        return XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
        )
    return GradientBoostingClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        random_state=42,
    )


# ─────────────────────────────────────────────────────────────
# Training
# ─────────────────────────────────────────────────────────────

def train(X: np.ndarray, y: np.ndarray, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    model = build_model()
    print("Training model ...")
    model.fit(X_train_s, y_train)

    # ── Evaluation ─────────────────────────────────
    y_pred     = model.predict(X_test_s)
    y_proba    = model.predict_proba(X_test_s)[:, 1]

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec  = recall_score(y_test, y_pred)
    f1   = f1_score(y_test, y_pred)
    auc  = roc_auc_score(y_test, y_proba)
    cm   = confusion_matrix(y_test, y_pred).tolist()

    metrics = {
        "accuracy":  round(acc,  4),
        "precision": round(prec, 4),
        "recall":    round(rec,  4),
        "f1_score":  round(f1,   4),
        "roc_auc":   round(auc,  4),
        "confusion_matrix": cm,
        "train_samples": len(X_train),
        "test_samples":  len(X_test),
        "features": FEATURE_NAMES,
        "model_type": type(model).__name__,
    }

    # ── Cross-validation ───────────────────────────
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X_train_s, y_train, cv=cv, scoring="accuracy")
    metrics["cv_mean_accuracy"] = round(float(cv_scores.mean()), 4)
    metrics["cv_std_accuracy"]  = round(float(cv_scores.std()),  4)

    print(classification_report(y_test, y_pred, target_names=["Benign", "Phishing"]))
    print(f"ROC-AUC: {auc:.4f}")
    print(f"CV Accuracy: {cv_scores.mean():.4f} +/- {cv_scores.std():.4f}")

    # ── Feature importance ─────────────────────────
    if hasattr(model, "feature_importances_"):
        importances = dict(zip(FEATURE_NAMES, model.feature_importances_.tolist()))
        metrics["feature_importances"] = dict(
            sorted(importances.items(), key=lambda x: x[1], reverse=True)[:20])

    # ── Persist ────────────────────────────────────
    with open(output_dir / "model.pkl",  "wb") as f:
        pickle.dump(model, f)
    with open(output_dir / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    with open(output_dir / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nModel saved -> {output_dir}/model.pkl")
    print(f"Metrics saved -> {output_dir}/metrics.json")
    return metrics


# ─────────────────────────────────────────────────────────────
# CLI entry-point
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train PhishGuard ML model")
    parser.add_argument("--phishing", help="CSV with phishing URLs")
    parser.add_argument("--benign",   help="CSV with benign URLs")
    parser.add_argument("--dataset",  help="Single CSV with both classes")
    parser.add_argument("--label",    default="label",
                        help="Label column name (0=benign, 1=phishing)")
    parser.add_argument("--url-col",  default="url",  help="URL column name")
    parser.add_argument("--output",   default="artifacts", help="Output directory")
    parser.add_argument("--max-per-class", type=int, default=None,
                        help="Optional cap per class for faster balanced training")
    args = parser.parse_args()

    if args.dataset:
        df = load_urls_from_csv(args.dataset, args.url_col, args.label)
        df = balance_classes(df, args.max_per_class)
    elif args.phishing and args.benign:
        ph = load_urls_from_csv(args.phishing, args.url_col, label_value=1)
        bn = load_urls_from_csv(args.benign,   args.url_col, label_value=0)
        # balance
        n = min(len(ph), len(bn))
        if args.max_per_class is not None:
            n = min(n, args.max_per_class)
        df = pd.concat([ph.sample(n, random_state=42), bn.sample(n, random_state=42)])
    else:
        parser.error("Provide --dataset OR (--phishing AND --benign)")

    print(f"Dataset: {len(df)} URLs  |  phishing={df['label'].sum()}  benign={(df['label']==0).sum()}")

    print("Extracting features ...")
    X_df = build_feature_matrix(df)
    X = X_df.values.astype(np.float32)
    y = df["label"].values.astype(np.int32)

    train(X, y, Path(args.output))
