"""Exploratory threshold study using a stratified split of training data only."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import platform
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from seguridad_pymes.ingestion import (
    DEFAULT_TRAIN_PATH,
    TrainingDataset,
    build_preprocessing_pipeline,
    load_unsw_training,
)


DEFAULT_OUTPUT_DIR = Path("data/processed/threshold_study")
SPLIT_SEED = 42
VALIDATION_SIZE = 0.20
MINIMUM_RECALL = 0.95
THRESHOLDS = tuple(value / 100 for value in range(50, 100, 5))
FIXED_PARAMETERS = {
    "n_estimators": 80,
    "max_depth": 24,
    "min_samples_leaf": 2,
    "max_features": "sqrt",
    "random_state": 42,
    "n_jobs": 1,
}
SELECTION_RULE = (
    "Among validation thresholds with recall >= 0.95, choose the lowest FPR; "
    "break ties by highest recall, then lowest threshold. If no threshold "
    "qualifies, select none."
)
LIMITATIONS = [
    "Thresholds are explored and selected on this same validation partition; "
    "its reported metrics are not an independent estimate after selection.",
    "The random stratified split does not measure temporal or cross-network "
    "generalization.",
    "Random Forest predict_proba scores are not necessarily calibrated "
    "probabilities.",
    "The official UNSW-NB15 test partition is not opened or used.",
    "This study does not change the production model, its metadata, inference, "
    "alerting, database, or dashboard behavior.",
]


@dataclass(frozen=True)
class ThresholdStudyResult:
    model_path: Path
    model_metadata_path: Path
    results_path: Path
    report_path: Path
    training_rows: int
    validation_rows: int
    selected_threshold: float | None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def split_training_data(
    dataset: TrainingDataset,
    *,
    validation_size: float = VALIDATION_SIZE,
    random_state: int = SPLIT_SEED,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """Split already validated training records with stratified sampling."""

    if not 0 < validation_size < 1:
        raise ValueError("validation_size debe estar entre 0 y 1.")
    counts = dataset.y_train.value_counts()
    if set(counts.index.tolist()) != {0, 1} or int(counts.min()) < 2:
        raise ValueError(
            "La partición requiere al menos dos registros válidos de cada clase."
        )
    X_train, X_validation, y_train, y_validation = train_test_split(
        dataset.X_train,
        dataset.y_train,
        test_size=validation_size,
        random_state=random_state,
        stratify=dataset.y_train,
    )
    return X_train, X_validation, y_train, y_validation


def _build_study_pipeline(dataset: TrainingDataset) -> Pipeline:
    preprocessing = build_preprocessing_pipeline(dataset).named_steps["features"]
    return Pipeline(
        [
            ("preprocessing", preprocessing),
            ("classifier", RandomForestClassifier(**FIXED_PARAMETERS)),
        ]
    )


def extract_attack_scores(model: Pipeline, records: pd.DataFrame) -> np.ndarray:
    """Return finite predict_proba scores for label 1, independent of class order."""

    if not hasattr(model, "predict_proba"):
        raise TypeError("El Pipeline no admite predict_proba.")
    classifier = model.named_steps.get("classifier")
    classes = getattr(classifier, "classes_", None)
    if classes is None or len(classes) != 2 or 1 not in classes:
        raise ValueError("El clasificador ajustado no declara ambas clases binarias.")
    probabilities = np.asarray(model.predict_proba(records), dtype=float)
    if probabilities.ndim != 2 or probabilities.shape != (len(records), len(classes)):
        raise ValueError("predict_proba devolvió una matriz incompatible.")
    scores = probabilities[:, list(classes).index(1)]
    if not np.isfinite(scores).all() or ((scores < 0) | (scores > 1)).any():
        raise ValueError("predict_proba devolvió scores de ataque inválidos.")
    return scores


def compute_threshold_metrics(
    labels: Sequence[int] | pd.Series,
    attack_scores: Sequence[float] | np.ndarray,
    threshold: float,
) -> dict[str, float | int]:
    """Calculate binary metrics with attack=1 and normal=0."""

    if not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("El umbral debe ser un valor finito entre 0 y 1.")
    y_true = np.asarray(labels)
    scores = np.asarray(attack_scores, dtype=float)
    if y_true.ndim != 1 or scores.ndim != 1 or len(y_true) != len(scores):
        raise ValueError("Etiquetas y scores deben ser vectores de igual longitud.")
    if len(y_true) == 0 or not np.isin(y_true, (0, 1)).all():
        raise ValueError("Se requieren etiquetas no vacías con clases 0 y 1.")
    if set(y_true.tolist()) != {0, 1}:
        raise ValueError("La validación debe contener ambas clases 0 y 1.")
    if not np.isfinite(scores).all() or ((scores < 0) | (scores > 1)).any():
        raise ValueError("Los scores deben ser finitos y estar entre 0 y 1.")

    predictions = (scores >= threshold).astype("int64")
    matrix = confusion_matrix(y_true, predictions, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "threshold": float(threshold),
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "alerts": fp + tp,
    }


def select_threshold(
    results: Sequence[dict[str, float | int]],
) -> float | None:
    """Apply the predeclared recall floor and deterministic tie breakers."""

    eligible = [row for row in results if float(row["recall"]) >= MINIMUM_RECALL]
    if not eligible:
        return None
    selected = min(
        eligible,
        key=lambda row: (
            float(row["fpr"]),
            -float(row["recall"]),
            float(row["threshold"]),
        ),
    )
    return float(selected["threshold"])


def _results_csv(results: Sequence[dict[str, float | int]]) -> str:
    output = io.StringIO(newline="")
    fields = (
        "threshold",
        "tn",
        "fp",
        "fn",
        "tp",
        "precision",
        "recall",
        "f1",
        "fpr",
        "alerts",
    )
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(results)
    return output.getvalue()


def _write_new_text(path: Path, content: str) -> None:
    with path.open("x", encoding="utf-8", newline="") as destination:
        destination.write(content)


def run_threshold_study(
    train_path: str | Path = DEFAULT_TRAIN_PATH,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
) -> ThresholdStudyResult:
    """Train and analyze a study-only model; never reads the official test CSV."""

    train_path = Path(train_path)
    output_dir = Path(output_dir)
    if output_dir.exists():
        raise FileExistsError(
            f"La carpeta del estudio ya existe y no se sobrescribirá: {output_dir}"
        )

    training_file_hash = _sha256(train_path)
    dataset = load_unsw_training(train_path)
    X_train, X_validation, y_train, y_validation = split_training_data(dataset)
    train_partition = TrainingDataset(
        X_train=X_train,
        y_train=y_train,
        numeric_columns=dataset.numeric_columns,
        categorical_columns=dataset.categorical_columns,
        excluded_columns=dataset.excluded_columns,
        train_report=dataset.train_report,
    )
    model = _build_study_pipeline(train_partition)
    started = time.perf_counter()
    model.fit(X_train, y_train)
    training_time_seconds = time.perf_counter() - started

    attack_scores = extract_attack_scores(model, X_validation)
    results = [
        compute_threshold_metrics(y_validation, attack_scores, threshold)
        for threshold in THRESHOLDS
    ]
    selected_threshold = select_threshold(results)

    model_name = "threshold_study_random_forest.joblib"
    model_path = output_dir / model_name
    metadata_path = output_dir / f"{model_name}.metadata.json"
    results_path = output_dir / "threshold_metrics.csv"
    report_path = output_dir / "threshold_study_report.json"

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(exist_ok=False)
    with model_path.open("xb") as destination:
        joblib.dump(model, destination)
    model_hash = _sha256(model_path)

    training_counts = {
        str(int(label)): int(count)
        for label, count in y_train.value_counts().sort_index().items()
    }
    validation_counts = {
        str(int(label)): int(count)
        for label, count in y_validation.value_counts().sort_index().items()
    }
    metadata: dict[str, Any] = {
        "study": "exploratory_random_forest_threshold_analysis",
        "dataset": {
            "training_file": train_path.name,
            "training_file_sha256": training_file_hash,
            "test_file_used": False,
            "rows_read": dataset.train_report.rows_read,
            "valid_rows": len(dataset.X_train),
            "dropped_by_reason": dataset.train_report.dropped_by_reason,
        },
        "split": {
            "method": "stratified train_test_split",
            "training_fraction": 0.80,
            "validation_fraction": VALIDATION_SIZE,
            "random_state": SPLIT_SEED,
            "training_rows": len(X_train),
            "validation_rows": len(X_validation),
            "training_class_counts": training_counts,
            "validation_class_counts": validation_counts,
        },
        "model": {
            "file": model_path.name,
            "sha256": model_hash,
            "parameters": FIXED_PARAMETERS,
            "training_time_seconds": training_time_seconds,
            "training_time_scope": "Pipeline.fit on training partition only",
            "input_features": list(X_train.columns),
        },
        "libraries": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "pandas": pd.__version__,
            "numpy": np.__version__,
            "joblib": joblib.__version__,
        },
        "methodology": {
            "positive_class": {"label": 1, "meaning": "attack"},
            "threshold_rule": "predict attack when attack_score >= threshold",
            "thresholds": list(THRESHOLDS),
            "selection_rule": SELECTION_RULE,
            "minimum_validation_recall": MINIMUM_RECALL,
            "limitations": LIMITATIONS,
        },
    }
    _write_new_text(
        metadata_path,
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
    )
    _write_new_text(results_path, _results_csv(results))
    table_hash = _sha256(results_path)
    report = {
        "study": "exploratory_random_forest_threshold_analysis",
        "model_file": model_path.name,
        "model_sha256": model_hash,
        "model_metadata_file": metadata_path.name,
        "model_metadata_sha256": _sha256(metadata_path),
        "training_file": train_path.name,
        "training_file_sha256": training_file_hash,
        "threshold_results_file": results_path.name,
        "threshold_results_sha256": table_hash,
        "split": metadata["split"],
        "training_time_seconds": training_time_seconds,
        "training_time_scope": "Pipeline.fit on training partition only",
        "selection_rule": SELECTION_RULE,
        "minimum_validation_recall": MINIMUM_RECALL,
        "selected_threshold": selected_threshold,
        "selection_status": (
            "selected_on_validation" if selected_threshold is not None else "none_met_recall_floor"
        ),
        "threshold_metrics": results,
        "limitations": LIMITATIONS,
    }
    _write_new_text(report_path, json.dumps(report, ensure_ascii=False, indent=2) + "\n")

    return ThresholdStudyResult(
        model_path=model_path,
        model_metadata_path=metadata_path,
        results_path=results_path,
        report_path=report_path,
        training_rows=len(X_train),
        validation_rows=len(X_validation),
        selected_threshold=selected_threshold,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Estudio exploratorio de umbrales usando una partición estratificada "
            "del CSV oficial de entrenamiento; no abre el CSV oficial de prueba."
        )
    )
    parser.add_argument("--train", type=Path, default=DEFAULT_TRAIN_PATH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()
    result = run_threshold_study(args.train, args.output_dir)
    print(f"Modelo de estudio: {result.model_path}")
    print(f"Metadatos: {result.model_metadata_path}")
    print(f"Métricas por umbral: {result.results_path}")
    print(f"Informe: {result.report_path}")
    print(
        "Umbral seleccionado en validación: "
        + (
            f"{result.selected_threshold:.2f}"
            if result.selected_threshold is not None
            else "ninguno cumple recall >= 0.95"
        )
    )


if __name__ == "__main__":
    main()
