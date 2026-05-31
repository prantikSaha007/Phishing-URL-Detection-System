"""
Evaluate a trained PhishGuard model on a labeled URL dataset.

Usage:
    python evaluate.py --dataset data/malicious_and_benign_urls.csv --url-col url --label label
"""

import argparse
import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from features import FEATURE_NAMES, extract_features
from train import normalize_labels


def build_feature_matrix(urls: pd.Series) -> pd.DataFrame:
    rows = []
    for url in urls.astype(str):
        try:
            rows.append(extract_features(url))
        except Exception:
            rows.append({k: 0.0 for k in FEATURE_NAMES})
    return pd.DataFrame(rows, columns=FEATURE_NAMES).fillna(0)


def exclude_training_sample(df: pd.DataFrame, max_per_class: int) -> pd.DataFrame:
    """Remove the deterministic balanced sample used by train.py."""
    train_parts = []
    for _, group in df.groupby("label", sort=False):
        n = min(len(group), max_per_class)
        train_parts.append(group.sample(n=n, random_state=42))

    train_index = pd.concat(train_parts).index
    return df.drop(index=train_index).reset_index(drop=True)


def main():
    parser = argparse.ArgumentParser(description="Evaluate PhishGuard model")
    parser.add_argument("--dataset", required=True, help="CSV dataset path")
    parser.add_argument("--url-col", default="url", help="URL column name")
    parser.add_argument("--label", default="label", help="Label column name")
    parser.add_argument("--artifacts", default="../backend/artifacts",
                        help="Folder containing model.pkl and scaler.pkl")
    parser.add_argument("--sample", type=int, default=None,
                        help="Optional random sample size for faster evaluation")
    parser.add_argument("--exclude-train-max-per-class", type=int, default=None,
                        help="Exclude the deterministic balanced training sample")
    parser.add_argument("--threshold", type=float, default=0.65,
                        help="Probability threshold for phishing")
    parser.add_argument("--output", default=None, help="Optional JSON output path")
    args = parser.parse_args()

    df = pd.read_csv(args.dataset)
    if args.url_col not in df.columns:
        raise ValueError(f"URL column not found: {args.url_col}")
    if args.label not in df.columns:
        raise ValueError(f"Label column not found: {args.label}")

    df = pd.DataFrame({
        "url": df[args.url_col].astype(str),
        "label": normalize_labels(df[args.label]),
    }).dropna()

    if args.exclude_train_max_per_class:
        df = exclude_training_sample(df, args.exclude_train_max_per_class)

    if args.sample and len(df) > args.sample:
        df = df.sample(n=args.sample, random_state=123).reset_index(drop=True)

    artifacts = Path(args.artifacts)
    with open(artifacts / "model.pkl", "rb") as f:
        model = pickle.load(f)
    with open(artifacts / "scaler.pkl", "rb") as f:
        scaler = pickle.load(f)

    print(f"Dataset rows: {len(df)}")
    print("Class counts:")
    print(df["label"].value_counts().sort_index().rename(index={0: "benign", 1: "phishing"}))
    print("Extracting features ...")

    X = build_feature_matrix(df["url"]).values.astype(np.float32)
    y_true = df["label"].values.astype(np.int32)
    y_proba = model.predict_proba(scaler.transform(X))[:, 1]
    y_pred = (y_proba >= args.threshold).astype(np.int32)

    report = {
        "rows": int(len(df)),
        "threshold": args.threshold,
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, y_proba)), 4),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
        "class_counts": {
            "benign": int((y_true == 0).sum()),
            "phishing": int((y_true == 1).sum()),
        },
    }

    print(classification_report(y_true, y_pred, target_names=["Benign", "Phishing"], zero_division=0))
    print(f"ROC-AUC: {report['roc_auc']:.4f}")
    print(f"Confusion matrix [[TN, FP], [FN, TP]]: {report['confusion_matrix']}")

    mistakes = df.copy()
    mistakes["score"] = y_proba
    mistakes["pred"] = y_pred
    false_positives = mistakes[(mistakes.label == 0) & (mistakes.pred == 1)].head(10)
    false_negatives = mistakes[(mistakes.label == 1) & (mistakes.pred == 0)].head(10)
    report["false_positive_examples"] = false_positives[["url", "score"]].to_dict("records")
    report["false_negative_examples"] = false_negatives[["url", "score"]].to_dict("records")

    output = Path(args.output) if args.output else artifacts / "evaluation.json"
    with open(output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"Saved evaluation -> {output}")


if __name__ == "__main__":
    main()
