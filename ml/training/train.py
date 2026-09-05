from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(ROOT / "ml" / "datasets"))

from app.services.features import FEATURE_ORDER, extract_features, vectorize  # noqa: E402
from app.utils.url_parser import URLParseError, parse_url  # noqa: E402
import generate_demo  # noqa: E402

DATA = ROOT / "ml" / "datasets" / "demo_urls.csv"
MODEL_OUT = ROOT / "ml" / "models" / "phishguard_model.joblib"
METRICS_OUT = ROOT / "ml" / "evaluation" / "metrics.json"
IMPORTANCE_OUT = ROOT / "ml" / "evaluation" / "feature_importance.json"


def load_xy(path: Path) -> tuple[np.ndarray, np.ndarray]:
    df = pd.read_csv(path)
    if "url" not in df.columns or "label" not in df.columns:
        raise SystemExit("Dataset must have columns: url,label")
    xs: list[list[float]] = []
    ys: list[int] = []
    for url, label in zip(df["url"].astype(str), df["label"].astype(int)):
        try:
            parsed = parse_url(url)
            feats = extract_features(parsed)
            xs.append(vectorize(feats))
            ys.append(int(label))
        except URLParseError:
            continue
    return np.array(xs, dtype=float), np.array(ys, dtype=int)


def candidates():
    models = {
        "random_forest": RandomForestClassifier(
            n_estimators=180,
            max_depth=14,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        ),
        "logreg": Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "clf",
                    LogisticRegression(max_iter=400, class_weight="balanced", random_state=42),
                ),
            ]
        ),
        "gradient_boosting": GradientBoostingClassifier(random_state=42),
    }
    try:
        from xgboost import XGBClassifier

        models["xgboost"] = XGBClassifier(
            n_estimators=180,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.9,
            colsample_bytree=0.9,
            objective="multi:softprob",
            eval_metric="mlogloss",
            random_state=42,
            n_jobs=-1,
        )
    except Exception:
        pass
    return models


def main() -> None:
    if not DATA.exists():
        generate_demo.main()
    X, y = load_xy(DATA)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    results = []
    best_name = None
    best_model = None
    best_f1 = -1.0
    best_pred = None
    for name, model in candidates().items():
        model.fit(X_train, y_train)
        pred = model.predict(X_test)
        proba = model.predict_proba(X_test) if hasattr(model, "predict_proba") else None
        f1 = f1_score(y_test, pred, average="macro")
        acc = accuracy_score(y_test, pred)
        prec, rec, _, _ = precision_recall_fscore_support(y_test, pred, average="macro", zero_division=0)
        auc = None
        if proba is not None and len(np.unique(y_test)) > 1:
            try:
                auc = float(roc_auc_score(y_test, proba, multi_class="ovr", average="macro"))
            except Exception:
                auc = None
        cm = confusion_matrix(y_test, pred, labels=[0, 1, 2]).tolist()
        report = classification_report(y_test, pred, labels=[0, 1, 2], output_dict=True, zero_division=0)
        results.append(
            {
                "name": name,
                "accuracy": float(acc),
                "precision_macro": float(prec),
                "recall_macro": float(rec),
                "f1_macro": float(f1),
                "roc_auc_ovr_macro": auc,
                "confusion_matrix": cm,
                "report": report,
            }
        )
        print(f"{name}: acc={acc:.3f} f1={f1:.3f} auc={auc}")
        if f1 > best_f1:
            best_f1 = f1
            best_name = name
            best_model = model
            best_pred = pred

    assert best_model is not None and best_name is not None and best_pred is not None
    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    METRICS_OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model": best_model,
        "model_name": best_name,
        "feature_names": FEATURE_ORDER,
        "dataset": str(DATA.name),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "classes": [0, 1, 2],
        "notes": "Trained on a synthetic DEMO dataset. Not production threat intelligence.",
    }
    joblib.dump(payload, MODEL_OUT)

    fn_phishing = int(sum((y_test == 2) & (best_pred != 2)))
    metrics = {
        "dataset": DATA.name,
        "dataset_rows": int(len(y)),
        "train_size": int(len(y_train)),
        "test_size": int(len(y_test)),
        "class_distribution": {
            "legitimate": int((y == 0).sum()),
            "suspicious": int((y == 1).sum()),
            "phishing": int((y == 2).sum()),
        },
        "selected_model": best_name,
        "split": "stratified 75/25, random_state=42",
        "candidates": results,
        "false_negatives_phishing": fn_phishing,
        "false_negative_note": (
            "A false negative may allow a malicious URL to reach a user. "
            "Phishing recall is therefore more important than headline accuracy."
        ),
        "disclaimer": (
            "These figures are measured on a synthetic development dataset. "
            "They must not be presented as production or real-world accuracy."
        ),
        "feature_count": len(FEATURE_ORDER),
    }
    METRICS_OUT.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    named = getattr(best_model, "named_steps", None)
    clf = named["clf"] if named and "clf" in named else best_model
    if hasattr(clf, "feature_importances_"):
        ranked = sorted(zip(FEATURE_ORDER, clf.feature_importances_), key=lambda x: x[1], reverse=True)
        IMPORTANCE_OUT.write_text(
            json.dumps([{"feature": n, "importance": float(v)} for n, v in ranked], indent=2),
            encoding="utf-8",
        )
    print(f"Saved model {best_name} -> {MODEL_OUT}")


if __name__ == "__main__":
    main()
