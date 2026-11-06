from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

from app.features import extract_features


FEATURE_COLUMNS = (
    "url_length",
    "uses_https",
    "is_ip_host",
    "subdomain_count",
    "suspicious_keyword_count",
    "has_userinfo",
    "has_punycode",
)
POSITIVE_LABELS = {"1", "phishing", "malicious"}
NEGATIVE_LABELS = {"0", "benign", "legitimate"}


def load_dataset(path: Path) -> tuple[list[list[int]], list[int]]:
    rows: list[list[int]] = []
    labels: list[int] = []
    with path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or not {"url", "label"}.issubset(reader.fieldnames):
            raise ValueError("CSV must contain 'url' and 'label' columns.")

        for line_number, row in enumerate(reader, start=2):
            label = (row.get("label") or "").strip().lower()
            if label not in POSITIVE_LABELS | NEGATIVE_LABELS:
                raise ValueError(
                    f"Unsupported label on CSV line {line_number}: {label!r}. "
                    "Use phishing/malicious/1 or legitimate/benign/0."
                )
            try:
                features = extract_features((row.get("url") or "").strip())
            except ValueError as exc:
                raise ValueError(f"Invalid URL on CSV line {line_number}: {exc}") from exc

            values = features.to_dict()
            rows.append(
                [
                    int(values[name])
                    for name in FEATURE_COLUMNS
                ]
            )
            labels.append(int(label in POSITIVE_LABELS))

    if not rows:
        raise ValueError("The CSV contains no labeled URL rows.")
    if set(labels) != {0, 1}:
        raise ValueError("The dataset must contain both phishing and legitimate examples.")
    return rows, labels


def benchmark(path: Path, test_size: float = 0.25) -> dict[str, Any]:
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import (
            accuracy_score,
            confusion_matrix,
            f1_score,
            precision_score,
            recall_score,
            roc_auc_score,
        )
        from sklearn.model_selection import train_test_split
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler
        from sklearn.svm import SVC
        from sklearn.tree import DecisionTreeClassifier
    except ImportError as exc:
        raise RuntimeError(
            "Install the optional ML dependencies with "
            "'python -m pip install -r ml-requirements.txt'."
        ) from exc

    if not 0.1 <= test_size <= 0.5:
        raise ValueError("--test-size must be between 0.1 and 0.5.")

    features, labels = load_dataset(path)
    class_counts = {label: labels.count(label) for label in (0, 1)}
    if min(class_counts.values()) < 2:
        raise ValueError("Each class needs at least two examples for a stratified split.")

    x_train, x_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=test_size,
        random_state=42,
        stratify=labels,
    )
    models: dict[str, Any] = {
        "Logistic Regression": make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=1000, random_state=42)
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=12, class_weight="balanced", random_state=42
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1
        ),
        "SVM": make_pipeline(
            StandardScaler(), SVC(class_weight="balanced", probability=True, random_state=42)
        ),
    }

    try:
        from xgboost import XGBClassifier
    except ImportError:
        xgboost_status = "skipped: install xgboost to include this model"
    else:
        models["XGBoost"] = XGBClassifier(
            n_estimators=200,
            max_depth=5,
            learning_rate=0.1,
            eval_metric="logloss",
            random_state=42,
        )
        xgboost_status = "included"

    results: dict[str, Any] = {}
    for name, model in models.items():
        model.fit(x_train, y_train)
        prediction = model.predict(x_test)
        probabilities = model.predict_proba(x_test)[:, 1]
        results[name] = {
            "accuracy": round(float(accuracy_score(y_test, prediction)), 4),
            "precision": round(float(precision_score(y_test, prediction, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, prediction, zero_division=0)), 4),
            "f1": round(float(f1_score(y_test, prediction, zero_division=0)), 4),
            "roc_auc": round(float(roc_auc_score(y_test, probabilities)), 4),
            "confusion_matrix": confusion_matrix(y_test, prediction).tolist(),
        }

    return {
        "dataset": str(path),
        "rows": len(labels),
        "train_rows": len(y_train),
        "test_rows": len(y_test),
        "positive_label": "phishing/malicious/1",
        "feature_columns": list(FEATURE_COLUMNS),
        "random_state": 42,
        "xgboost": xgboost_status,
        "results": results,
        "warning": (
            "Metrics depend on this dataset and split. Check for duplicate or near-duplicate "
            "URLs across splits before using results as evidence of generalization."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare phishing classifiers using a labeled URL CSV."
    )
    parser.add_argument("csv_path", type=Path, help="CSV file with url,label columns")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--output", type=Path, help="Optional path to save the JSON report")
    args = parser.parse_args()

    try:
        report = benchmark(args.csv_path, args.test_size)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(report, indent=2)
    print(rendered)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
