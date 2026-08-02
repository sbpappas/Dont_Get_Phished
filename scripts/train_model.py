#!/usr/bin/env python3
"""Train the PhishGuard ML classifier.

Data source: the "Phishing Dataset" published by Vrbancic, Zelenko &
Podgorelec, "Datasets for phishing websites detection", Data in Brief,
2020 (https://doi.org/10.1016/j.dib.2020.106438), mirrored at
https://github.com/GregaVrbancic/Phishing-Dataset. We train only on the
subset of its columns that PhishGuard can recompute live from a URL
(see phishguard/feature_schema.py::FEATURE_ORDER) -- the rest of the
original 111 columns (Google-index checks, ASN, etc.) are dropped so
training and inference stay consistent.

Usage:
    python scripts/train_model.py
    python scripts/train_model.py --data data/dataset_small.csv --out models/model.joblib
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from phishguard.feature_schema import FEATURE_ORDER, LABEL_COLUMN  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default="data/dataset_small.csv")
    parser.add_argument("--out", default="models/model.joblib")
    parser.add_argument("--metadata-out", default="models/metadata.json")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    print(f"Loading {args.data} ...")
    df = pd.read_csv(args.data)

    missing = [c for c in FEATURE_ORDER if c not in df.columns]
    if missing:
        raise SystemExit(f"Dataset is missing expected columns: {missing}")

    X = df[FEATURE_ORDER]
    y = df[LABEL_COLUMN]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.random_state, stratify=y
    )

    print(f"Training RandomForestClassifier on {len(X_train)} rows, "
          f"{len(FEATURE_ORDER)} features ...")
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        min_samples_leaf=5,
        n_jobs=-1,
        random_state=args.random_state,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]
    report = classification_report(y_test, y_pred, target_names=["legitimate", "phishing"])
    auc = roc_auc_score(y_test, y_proba)

    print("\n" + report)
    print(f"ROC AUC: {auc:.4f}")

    importances = sorted(
        zip(FEATURE_ORDER, clf.feature_importances_), key=lambda t: -t[1]
    )
    print("\nTop 10 most important features:")
    for name, imp in importances[:10]:
        print(f"  {name:<28} {imp:.4f}")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, out_path)
    print(f"\nSaved model to {out_path}")

    metadata = {
        "feature_order": FEATURE_ORDER,
        "label_column": LABEL_COLUMN,
        "n_train": len(X_train),
        "n_test": len(X_test),
        "roc_auc": round(auc, 4),
        "classification_report": report,
        "top_features": [{"name": n, "importance": round(float(i), 4)} for n, i in importances],
        "source_dataset": "GregaVrbancic/Phishing-Dataset (dataset_small.csv)",
        "model": "sklearn.ensemble.RandomForestClassifier",
    }
    Path(args.metadata_out).write_text(json.dumps(metadata, indent=2))
    print(f"Saved metadata to {args.metadata_out}")


if __name__ == "__main__":
    main()
