"""Medición reproducible de tiempo y memoria para inferencia por lotes."""

from __future__ import annotations

import argparse
import csv
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Sequence

import numpy as np
import pandas as pd
import psutil

from seguridad_pymes.training import DEFAULT_MODEL_PATH, load_trained_model


DEFAULT_SAMPLE_SIZES = (100, 1000, 10000, 50000)
DEFAULT_RESOURCE_OUTPUT = Path("data/processed/inference_resources.csv")
MEMORY_SAMPLE_INTERVAL_SECONDS = 0.01


@dataclass(frozen=True)
class ResourceMeasurement:
    """Uso de recursos observado para una llamada de inferencia."""

    sample_size: int
    elapsed_seconds: float
    elapsed_ms_per_record: float
    baseline_rss_mib: float
    peak_rss_mib: float
    peak_rss_delta_mib: float


def measure_operation(
    operation: Callable[[], object],
    *,
    sample_size: int,
    process: psutil.Process | None = None,
) -> ResourceMeasurement:
    """Mide tiempo y pico RSS aproximado mientras ejecuta una operación.

    RSS se muestrea en un hilo auxiliar cada 10 ms; asignaciones más breves
    pueden no quedar reflejadas. La función no modifica el resultado de operación.
    """

    if sample_size <= 0:
        raise ValueError("sample_size debe ser mayor que cero.")
    process = process or psutil.Process()
    baseline_rss = process.memory_info().rss
    peak_rss = baseline_rss
    stop_sampling = threading.Event()

    def sample_memory() -> None:
        nonlocal peak_rss
        while not stop_sampling.is_set():
            try:
                peak_rss = max(peak_rss, process.memory_info().rss)
            except psutil.Error:
                return
            stop_sampling.wait(MEMORY_SAMPLE_INTERVAL_SECONDS)

    sampler = threading.Thread(target=sample_memory, daemon=True)
    sampler.start()
    started = time.perf_counter()
    try:
        operation()
    finally:
        elapsed = time.perf_counter() - started
        stop_sampling.set()
        sampler.join()
        try:
            peak_rss = max(peak_rss, process.memory_info().rss)
        except psutil.Error as error:
            raise RuntimeError(f"No se pudo leer memoria RSS del proceso: {error}") from error

    mib = 1024 * 1024
    return ResourceMeasurement(
        sample_size=sample_size,
        elapsed_seconds=elapsed,
        elapsed_ms_per_record=elapsed * 1000 / sample_size,
        baseline_rss_mib=baseline_rss / mib,
        peak_rss_mib=peak_rss / mib,
        peak_rss_delta_mib=max(0, peak_rss - baseline_rss) / mib,
    )


def benchmark_inference(
    model_path: str | Path,
    csv_path: str | Path,
    sample_sizes: Sequence[int] = DEFAULT_SAMPLE_SIZES,
    output_path: str | Path = DEFAULT_RESOURCE_OUTPUT,
) -> list[ResourceMeasurement]:
    """Mide Pipeline.predict por tamaños sobre filas reales de un CSV compatible.

    El archivo de entrada debe contener características del modelo y puede
    incluir `id`, `label` y `attack_cat`, que se descartan. No se usa para ajustar
    el modelo ni producir métricas de clasificación.
    """

    if not sample_sizes:
        raise ValueError("Debe proporcionar al menos un tamaño de muestra.")
    if any(size <= 0 for size in sample_sizes):
        raise ValueError("Todos los tamaños de muestra deben ser positivos.")
    if list(sample_sizes) != sorted(set(sample_sizes)):
        raise ValueError("Los tamaños deben ser únicos y estar en orden ascendente.")

    model_path = Path(model_path)
    csv_path = Path(csv_path)
    output_path = Path(output_path)
    if output_path.resolve() in {model_path.resolve(), csv_path.resolve()}:
        raise ValueError(
            "El archivo de salida no puede sobrescribir el modelo ni el CSV de entrada."
        )
    if output_path.exists():
        raise FileExistsError(
            f"El archivo de mediciones ya existe y no será sobrescrito: {output_path}"
        )
    model = load_trained_model(model_path)
    preprocessing = model.named_steps["preprocessing"]
    expected = tuple(str(name) for name in preprocessing.feature_names_in_)
    transformers = preprocessing.named_transformers_
    numeric = tuple(
        str(name)
        for name in getattr(transformers.get("numeric"), "feature_names_in_", ())
    )

    try:
        raw = pd.read_csv(csv_path, dtype="string", encoding="utf-8-sig", low_memory=False)
    except (OSError, UnicodeError, pd.errors.ParserError, pd.errors.EmptyDataError) as error:
        raise ValueError(f"No se pudo leer el CSV de medición {csv_path}: {error}") from error
    removable = [
        column for column in raw.columns
        if column.casefold() in {"id", "label", "attack_cat"}
    ]
    predictors = raw.drop(columns=removable)
    missing = [name for name in expected if name not in predictors.columns]
    unexpected = [name for name in predictors.columns if name not in expected]
    if missing or unexpected:
        raise ValueError(
            f"El CSV no coincide con el modelo. Faltantes: {missing}; "
            f"no esperadas: {unexpected}."
        )
    predictors = predictors.loc[:, expected]
    if predictors.empty:
        raise ValueError("El CSV no contiene filas para medir.")
    if predictors.isna().any(axis=None):
        raise ValueError("El CSV tiene valores vacíos en características requeridas.")

    for column in numeric:
        converted = pd.to_numeric(predictors[column], errors="coerce")
        if converted.isna().any() or not np.isfinite(converted.to_numpy(dtype=float)).all():
            raise ValueError(f"Valores numéricos inválidos en {column!r}.")
        predictors[column] = converted
    categorical = [column for column in expected if column not in numeric]
    for column in categorical:
        predictors[column] = predictors[column].astype("string")

    if max(sample_sizes) > len(predictors):
        raise ValueError(
            f"El tamaño máximo solicitado ({max(sample_sizes)}) excede las "
            f"{len(predictors)} filas disponibles."
        )

    measurements = []
    for size in sample_sizes:
        sample = predictors.iloc[:size]
        measurements.append(
            measure_operation(
                lambda sample=sample: model.predict(sample),
                sample_size=size,
            )
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(
            output,
            fieldnames=list(asdict(measurements[0]).keys()),
        )
        writer.writeheader()
        writer.writerows(asdict(item) for item in measurements)
    return measurements


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Mide tiempo y RSS de inferencia por lote sobre un CSV compatible; "
            "no calcula métricas de clasificación."
        )
    )
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_RESOURCE_OUTPUT)
    parser.add_argument(
        "--sample-sizes",
        type=int,
        nargs="+",
        default=list(DEFAULT_SAMPLE_SIZES),
        metavar="N",
    )
    args = parser.parse_args()
    results = benchmark_inference(
        args.model,
        args.csv,
        args.sample_sizes,
        args.output,
    )
    for result in results:
        print(
            f"n={result.sample_size}: {result.elapsed_seconds:.6f} s, "
            f"{result.elapsed_ms_per_record:.6f} ms/registro, "
            f"RSS pico={result.peak_rss_mib:.2f} MiB "
            f"(Δ {result.peak_rss_delta_mib:.2f} MiB)"
        )
    print(f"Mediciones guardadas en: {args.output}")


if __name__ == "__main__":
    main()
