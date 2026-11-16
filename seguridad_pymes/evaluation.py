"""Evaluación final de un Pipeline entrenado sobre el holdout UNSW-NB15."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline

from seguridad_pymes.ingestion import (
    DEFAULT_TEST_PATH,
    DatasetValidationError,
    DataQualityReport,
    load_unsw_test_for_model,
)
from seguridad_pymes.training import DEFAULT_MODEL_PATH, load_trained_model


DEFAULT_OUTPUT_DIR = Path("data/processed/evaluation")
METRIC_LIMITATIONS = {
    "precision": (
        "De las alertas emitidas, qué proporción fue ataque. Depende de la "
        "prevalencia y distribución del conjunto de prueba; una precisión alta "
        "en UNSW-NB15 no garantiza la misma proporción en una PYME."
    ),
    "recall": (
        "De los ataques etiquetados en prueba, qué proporción detectó el modelo. "
        "No mide gravedad y los ataques ausentes o distintos en redes reales "
        "pueden reducirlo."
    ),
    "f1_score": (
        "Media armónica de precision y recall para la clase ataque. No pondera "
        "costos operativos, severidad ni falsos positivos de forma asimétrica."
    ),
    "false_positive_rate": (
        "Proporción de tráfico normal que se marca como ataque (FP/(FP+TN)). "
        "Con tráfico normal muy abundante, una tasa pequeña aún puede generar "
        "muchas alertas; las etiquetas y condiciones del benchmark pueden no "
        "representar una PYME."
    ),
    "inference_time_seconds": (
        "Tiempo de pared de una llamada predict sobre todas las filas retenidas, "
        "incluyendo preprocesamiento del Pipeline. Es específico del equipo, "
        "carga del sistema y tamaño del lote; no equivale a latencia por paquete "
        "ni a monitoreo en tiempo real."
    ),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class EvaluationResult:
    """Métricas, conteo y artefactos de una evaluación ya ejecutada."""

    evaluated_samples: int
    confusion_matrix: tuple[tuple[int, int], tuple[int, int]]
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    inference_time_seconds: float
    inference_time_ms_per_sample: float
    test_report: DataQualityReport
    metrics_path: Path
    confusion_matrix_path: Path
    confusion_matrix_plot_path: Path
    metrics_plot_path: Path


def _pipeline_schema(
    model: Pipeline,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not isinstance(model, Pipeline):
        raise TypeError("El artefacto de modelo debe ser un sklearn Pipeline.")
    if not {"preprocessing", "classifier"}.issubset(model.named_steps):
        raise TypeError(
            "El Pipeline debe incluir los pasos 'preprocessing' y 'classifier'."
        )

    preprocessing = model.named_steps["preprocessing"]
    feature_names = getattr(preprocessing, "feature_names_in_", None)
    if feature_names is None:
        raise DatasetValidationError(
            "El preprocesador guardado no registra nombres de características de entrada."
        )
    expected_features = tuple(str(name) for name in feature_names)
    transformer = getattr(preprocessing, "named_transformers_", None)
    if transformer is None:
        raise DatasetValidationError("El preprocesador del modelo no está ajustado.")

    numeric_features = tuple(
        str(column)
        for column in getattr(transformer.get("numeric"), "feature_names_in_", ())
    )
    return expected_features, numeric_features


def _write_confusion_csv(path: Path, matrix: np.ndarray) -> None:
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.writer(output)
        writer.writerow(["true_label", "predicted_normal_0", "predicted_attack_1"])
        writer.writerow(["normal_0", int(matrix[0, 0]), int(matrix[0, 1])])
        writer.writerow(["attack_1", int(matrix[1, 0]), int(matrix[1, 1])])


def _write_confusion_svg(path: Path, matrix: np.ndarray) -> None:
    width, height = 720, 490
    left, top, cell = 250, 125, 155
    maximum = max(1, int(matrix.max()))
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<style>text{font-family:Segoe UI,Arial,sans-serif;fill:#172033}'
        '.title{font-size:24px;font-weight:700}.label{font-size:16px}'
        '.value{font-size:24px;font-weight:700}.small{font-size:13px}</style>',
        '<text x="360" y="42" text-anchor="middle" class="title">'
        "Matriz de confusión</text>",
        '<text x="405" y="88" text-anchor="middle" class="label">'
        "Predicción</text>",
        '<text x="327" y="112" text-anchor="middle" class="label">Normal (0)</text>',
        '<text x="482" y="112" text-anchor="middle" class="label">Ataque (1)</text>',
        '<text x="38" y="281" text-anchor="middle" class="label" '
        'transform="rotate(-90 38 281)">Etiqueta real</text>',
    ]
    for row, row_name in enumerate(("Normal (0)", "Ataque (1)")):
        y = top + row * cell
        parts.append(
            f'<text x="{left - 15}" y="{y + cell / 2 + 5}" text-anchor="end" '
            f'class="label">{row_name}</text>'
        )
        for column in range(2):
            x = left + column * cell
            value = int(matrix[row, column])
            intensity = int(238 - 95 * value / maximum)
            color = f"rgb({intensity},{min(248, intensity + 8)},{min(255, intensity + 17)})"
            parts.extend(
                [
                    f'<rect x="{x}" y="{y}" width="{cell}" height="{cell}" '
                    f'rx="8" fill="{color}" stroke="#ffffff" stroke-width="4"/>',
                    f'<text x="{x + cell / 2}" y="{y + cell / 2 + 8}" '
                    f'text-anchor="middle" class="value">{value}</text>',
                ]
            )
    parts.append(
        '<text x="360" y="465" text-anchor="middle" class="small">'
        "Filas: etiqueta real · Columnas: predicción</text>"
    )
    parts.append("</svg>")
    path.write_text("\n".join(parts), encoding="utf-8")


def _write_metrics_svg(path: Path, metrics: dict[str, float]) -> None:
    plotted = (
        ("Precision (ataque)", metrics["precision"]),
        ("Recall (ataque)", metrics["recall"]),
        ("F1-score (ataque)", metrics["f1_score"]),
        ("Tasa falsos positivos", metrics["false_positive_rate"]),
    )
    width, height = 820, 410
    left, right, top, bar_height, gap = 250, 90, 78, 45, 25
    chart_width = width - left - right
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<style>text{font-family:Segoe UI,Arial,sans-serif;fill:#172033}'
        '.title{font-size:23px;font-weight:700}.label{font-size:15px}'
        '.value{font-size:14px;font-weight:700}.tick{font-size:12px;fill:#596579}</style>',
        '<text x="410" y="38" text-anchor="middle" class="title">'
        "Métricas de clasificación en prueba</text>",
    ]
    for index, (name, value) in enumerate(plotted):
        y = top + index * (bar_height + gap)
        bar_width = chart_width * max(0.0, min(1.0, value))
        parts.extend(
            [
                f'<text x="{left - 12}" y="{y + bar_height / 2 + 5}" '
                f'text-anchor="end" class="label">{name}</text>',
                f'<rect x="{left}" y="{y}" width="{chart_width}" height="{bar_height}" '
                'rx="5" fill="#e8edf4"/>',
                f'<rect x="{left}" y="{y}" width="{bar_width:.2f}" height="{bar_height}" '
                'rx="5" fill="#2463a6"/>',
                f'<text x="{left + bar_width + 9:.2f}" y="{y + bar_height / 2 + 5}" '
                f'class="value">{value:.4f}</text>',
            ]
        )
    axis_y = top + 4 * (bar_height + gap) - gap + 12
    for tick in (0.0, 0.25, 0.5, 0.75, 1.0):
        x = left + chart_width * tick
        parts.extend(
            [
                f'<line x1="{x:.2f}" y1="{top - 8}" x2="{x:.2f}" '
                f'y2="{axis_y}" stroke="#d9e0e9" stroke-width="1"/>',
                f'<text x="{x:.2f}" y="{axis_y + 20}" text-anchor="middle" '
                f'class="tick">{tick:.2f}</text>',
            ]
        )
    parts.extend(["</svg>"])
    path.write_text("\n".join(parts), encoding="utf-8")


def evaluate_model(
    model_path: str | Path = DEFAULT_MODEL_PATH,
    test_path: str | Path = DEFAULT_TEST_PATH,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
) -> EvaluationResult:
    """Evalúa el Pipeline guardado con la partición de prueba reservada.

    No ajusta el Pipeline ni sus parámetros. Cualquier fila inválida se excluye
    con conteo por motivo; las métricas usan solo las filas retenidas.
    """

    model_path = Path(model_path)
    test_path = Path(test_path)
    output_dir = Path(output_dir)
    output_paths = (
        output_dir / "metrics.json",
        output_dir / "confusion_matrix.csv",
        output_dir / "confusion_matrix.svg",
        output_dir / "classification_metrics.svg",
    )
    existing_outputs = [path for path in output_paths if path.exists()]
    if existing_outputs:
        raise FileExistsError(
            "La evaluación no sobrescribe resultados existentes: "
            + ", ".join(str(path) for path in existing_outputs)
        )
    model = load_trained_model(model_path)
    expected_features, numeric_features = _pipeline_schema(model)
    test = load_unsw_test_for_model(
        test_path=test_path,
        expected_features=expected_features,
        numeric_features=numeric_features,
    )
    if set(test.y_test.unique().tolist()) != {0, 1}:
        raise ValueError(
            "La partición evaluable debe contener ambas clases normal (0) y "
            f"ataque (1); clases encontradas: {sorted(test.y_test.unique().tolist())}."
        )

    started = time.perf_counter()
    predictions = model.predict(test.X_test)
    inference_time_seconds = time.perf_counter() - started
    matrix = confusion_matrix(test.y_test, predictions, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    precision = float(precision_score(test.y_test, predictions, pos_label=1, zero_division=0))
    recall = float(recall_score(test.y_test, predictions, pos_label=1, zero_division=0))
    f1 = float(f1_score(test.y_test, predictions, pos_label=1, zero_division=0))
    if tn + fp == 0:
        raise ValueError("No hay muestras normales en prueba para calcular tasa de falsos positivos.")
    false_positive_rate = fp / (fp + tn)
    evaluated_samples = len(test.y_test)
    time_per_sample = inference_time_seconds * 1000 / evaluated_samples

    output_dir.mkdir(parents=True, exist_ok=True)
    (
        metrics_path,
        confusion_path,
        confusion_plot_path,
        metrics_plot_path,
    ) = output_paths
    _write_confusion_csv(confusion_path, matrix)
    _write_confusion_svg(confusion_plot_path, matrix)
    metric_values = {
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": false_positive_rate,
    }
    _write_metrics_svg(metrics_plot_path, metric_values)

    training_metadata_path = model_path.with_suffix(
        model_path.suffix + ".metadata.json"
    )
    training_metadata: dict[str, Any] | None = None
    if training_metadata_path.is_file():
        training_metadata = json.loads(
            training_metadata_path.read_text(encoding="utf-8")
        )

    payload: dict[str, Any] = {
        "dataset": "UNSW-NB15",
        "files": {
            "test_file": test_path.name,
            "test_file_sha256": _sha256(test_path),
            "model_file": model_path.name,
            "model_file_sha256": _sha256(model_path),
            "training_metadata_file": (
                training_metadata_path.name if training_metadata is not None else None
            ),
            "training_metadata_sha256": (
                _sha256(training_metadata_path)
                if training_metadata is not None
                else None
            ),
        },
        "training_metadata": training_metadata,
        "library_versions": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "pandas": pd.__version__,
            "numpy": np.__version__,
        },
        "evaluated_samples": evaluated_samples,
        "test_data_quality": {
            "rows_read": test.test_report.rows_read,
            "rows_kept": test.test_report.rows_kept,
            "rows_dropped": test.test_report.rows_dropped,
            "dropped_by_reason": test.test_report.dropped_by_reason,
        },
        "positive_class": {"label": 1, "meaning": "attack"},
        "confusion_matrix": {
            "labels": [0, 1],
            "label_names": ["normal", "attack"],
            "rows_are": "true labels",
            "columns_are": "predicted labels",
            "values": matrix.tolist(),
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
            "true_positive": tp,
        },
        "metrics": {
            **metric_values,
            "inference_time_seconds": inference_time_seconds,
            "inference_time_ms_per_sample": time_per_sample,
            "timing_method": (
                "Single perf_counter measurement of Pipeline.predict on all "
                "retained rows, including preprocessing; no warm-up."
            ),
        },
        "limitations": METRIC_LIMITATIONS,
        "methodology": {
            "test_set_used_for_training_or_tuning": False,
            "pipeline_fitted_during_evaluation": False,
            "invalid_rows_excluded": True,
            "metric_class": "positive label 1 (attack)",
            "false_positive_rate_formula": "FP / (FP + TN)",
        },
    }
    metrics_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return EvaluationResult(
        evaluated_samples=evaluated_samples,
        confusion_matrix=(
            (tn, fp),
            (fn, tp),
        ),
        precision=precision,
        recall=recall,
        f1_score=f1,
        false_positive_rate=false_positive_rate,
        inference_time_seconds=inference_time_seconds,
        inference_time_ms_per_sample=time_per_sample,
        test_report=test.test_report,
        metrics_path=metrics_path,
        confusion_matrix_path=confusion_path,
        confusion_matrix_plot_path=confusion_plot_path,
        metrics_plot_path=metrics_plot_path,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evalúa un Pipeline ya entrenado en el holdout UNSW-NB15."
    )
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--test", type=Path, default=DEFAULT_TEST_PATH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    result = evaluate_model(args.model, args.test, args.output_dir)
    print(f"Muestras evaluadas: {result.evaluated_samples}")
    print(f"Matriz de confusión [[TN, FP], [FN, TP]]: {result.confusion_matrix}")
    print(f"Precision (ataque): {result.precision:.6f}")
    print(f"Recall (ataque): {result.recall:.6f}")
    print(f"F1-score (ataque): {result.f1_score:.6f}")
    print(f"Tasa de falsos positivos: {result.false_positive_rate:.6f}")
    print(f"Tiempo de inferencia: {result.inference_time_seconds:.6f} s")
    print(f"Métricas JSON: {result.metrics_path}")
    print(f"Matriz CSV: {result.confusion_matrix_path}")
    print(f"Gráficos SVG: {result.confusion_matrix_plot_path}, {result.metrics_plot_path}")


if __name__ == "__main__":
    main()
