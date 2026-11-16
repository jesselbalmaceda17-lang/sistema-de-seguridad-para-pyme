"""Inferencia del Pipeline guardado y persistencia de alertas predichas."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline

from seguridad_pymes.database import (
    DEFAULT_DATABASE_PATH,
    complete_analysis_run,
    create_analysis_run,
    fail_analysis_run,
    initialize_database,
)
from seguridad_pymes.resources import ResourceMeasurement, measure_operation
from seguridad_pymes.training import (
    DEFAULT_MODEL_PATH,
    THRESHOLD_STUDY_MODEL_PATH,
    load_trained_model,
)


PRODUCTION_MODEL_ID = "production_random_forest"
THRESHOLD_STUDY_MODEL_ID = "threshold_study_random_forest"
CUSTOM_OVERRIDE_MODEL_ID = "custom_override"
PRODUCTION_MODEL_LABEL = "Definitivo — clasificación predeterminada"
THRESHOLD_STUDY_MODEL_LABEL = "Experimental — umbral 0.65"
PREDICT_RULE = "predict"
THRESHOLD_RULE = "predict_proba_gte"
THRESHOLD_STUDY_THRESHOLD = 0.65


@dataclass(frozen=True)
class InferenceRunResult:
    """Resumen de una inferencia real y su persistencia local."""

    run_id: str
    records_processed: int
    alerts_created: int
    predictions: tuple[int, ...]
    attack_scores: tuple[float | None, ...]
    database_path: Path
    resource_measurement: ResourceMeasurement | None = None
    model_id: str | None = None
    decision_rule: str | None = None
    decision_threshold: float | None = None
    model_sha256: str | None = None
    model_reference: str | None = None


@dataclass(frozen=True)
class ModelConfiguration:
    model_id: str
    label: str
    model_path: Path
    decision_rule: str
    decision_threshold: float | None


def model_configuration(
    model_id: str,
    *,
    model_path: str | Path | None = None,
) -> ModelConfiguration:
    if model_id == PRODUCTION_MODEL_ID:
        expected_path = DEFAULT_MODEL_PATH
        configuration = ModelConfiguration(
            model_id=PRODUCTION_MODEL_ID,
            label=PRODUCTION_MODEL_LABEL,
            model_path=Path(model_path) if model_path is not None else expected_path,
            decision_rule=PREDICT_RULE,
            decision_threshold=None,
        )
    elif model_id == THRESHOLD_STUDY_MODEL_ID:
        expected_path = THRESHOLD_STUDY_MODEL_PATH
        configuration = ModelConfiguration(
            model_id=THRESHOLD_STUDY_MODEL_ID,
            label=THRESHOLD_STUDY_MODEL_LABEL,
            model_path=Path(model_path) if model_path is not None else expected_path,
            decision_rule=THRESHOLD_RULE,
            decision_threshold=THRESHOLD_STUDY_THRESHOLD,
        )
    elif model_id == CUSTOM_OVERRIDE_MODEL_ID and model_path is not None:
        custom_path = Path(model_path)
        if custom_path.resolve() in {
            DEFAULT_MODEL_PATH.resolve(),
            THRESHOLD_STUDY_MODEL_PATH.resolve(),
        }:
            raise ValueError(
                "Los artefactos integrados deben usar su identificador de modelo "
                "registrado."
            )
        configuration = ModelConfiguration(
            model_id=CUSTOM_OVERRIDE_MODEL_ID,
            label=f"Override explícito — {model_path}",
            model_path=custom_path,
            decision_rule=PREDICT_RULE,
            decision_threshold=None,
        )
        return configuration
    else:
        raise ValueError(f"Identificador de modelo no reconocido: {model_id}.")

    if configuration.model_path.resolve() != expected_path.resolve():
        raise ValueError(
            f"El modelo {model_id} debe usar el artefacto autorizado "
            f"{expected_path}; no se cambiará de modelo silenciosamente."
        )
    return configuration


def infer_model_configuration(model_path: str | Path) -> ModelConfiguration:
    path = Path(model_path)
    if path.resolve() == DEFAULT_MODEL_PATH.resolve():
        return model_configuration(PRODUCTION_MODEL_ID, model_path=path)
    if path.resolve() == THRESHOLD_STUDY_MODEL_PATH.resolve():
        return model_configuration(THRESHOLD_STUDY_MODEL_ID, model_path=path)
    return model_configuration(CUSTOM_OVERRIDE_MODEL_ID, model_path=path)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as model_file:
        for chunk in iter(lambda: model_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _model_input_schema(
    model: Pipeline,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    preprocessing = model.named_steps.get("preprocessing")
    if preprocessing is None or not hasattr(preprocessing, "feature_names_in_"):
        raise ValueError(
            "El Pipeline no declara características de entrada en el preprocesador."
        )
    expected = tuple(str(column) for column in preprocessing.feature_names_in_)
    transformers = getattr(preprocessing, "named_transformers_", None)
    if transformers is None:
        raise ValueError("El preprocesador del Pipeline no está ajustado.")
    numeric = tuple(
        str(column)
        for column in getattr(transformers.get("numeric"), "feature_names_in_", ())
    )
    if not expected:
        raise ValueError("El Pipeline no tiene características de entrada.")
    if any(name.casefold() in {"label", "id", "attack_cat"} for name in expected):
        raise ValueError(
            "El esquema de inferencia contiene columnas excluidas "
            "(`label`, `id` o `attack_cat`)."
        )
    return expected, numeric


def _validate_records(
    records: pd.DataFrame,
    expected_features: tuple[str, ...],
    numeric_features: tuple[str, ...],
) -> pd.DataFrame:
    if records.empty:
        raise ValueError("No se puede ejecutar inferencia con cero registros.")
    if records.columns.has_duplicates:
        raise ValueError("Los registros contienen nombres de columna duplicados.")
    if any(column.casefold() in {"label", "id", "attack_cat"} for column in records.columns):
        raise ValueError(
            "Pase solo predictores al Pipeline; no incluya `label`, `id` ni "
            "`attack_cat`."
        )
    missing = [column for column in expected_features if column not in records.columns]
    unexpected = [column for column in records.columns if column not in expected_features]
    if missing or unexpected:
        raise ValueError(
            f"Columnas incompatibles con el Pipeline. Faltantes: {missing}; "
            f"no esperadas: {unexpected}."
        )

    validated = records.loc[:, expected_features].copy()
    if validated.isna().any(axis=None):
        raise ValueError("Los registros contienen valores faltantes.")
    for column in numeric_features:
        numeric_values = pd.to_numeric(validated[column], errors="coerce")
        values = numeric_values.to_numpy(dtype=float, na_value=np.nan)
        if not np.isfinite(values).all():
            raise ValueError(
                f"La característica numérica {column!r} contiene valores "
                "no numéricos o no finitos."
            )
        validated[column] = numeric_values
    categorical = [column for column in expected_features if column not in numeric_features]
    for column in categorical:
        validated[column] = validated[column].astype("string")
    return validated


def run_model_analysis(
    records: pd.DataFrame,
    record_ids: Sequence[str],
    *,
    source: str,
    model_path: str | Path = DEFAULT_MODEL_PATH,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
    model_id: str | None = None,
) -> InferenceRunResult:
    """Predice registros con el Pipeline y guarda una ejecución y sus alertas.

    Solo se insertan alertas para predicciones reales con clase 1 (ataque).
    `record_ids` identifica cada registro de entrada y no se pasa como predictor.
    """

    if len(record_ids) != len(records):
        raise ValueError("Debe proporcionarse exactamente un record_id por fila.")
    if any(not isinstance(record_id, str) or not record_id.strip() for record_id in record_ids):
        raise ValueError("Cada record_id debe ser un texto no vacío.")
    if len(set(record_ids)) != len(record_ids):
        raise ValueError("Los record_ids deben ser únicos en la ejecución.")
    if not source.strip():
        raise ValueError("source no puede estar vacío.")

    configuration = (
        infer_model_configuration(model_path)
        if model_id is None
        else model_configuration(model_id, model_path=model_path)
    )
    if (
        configuration.decision_rule == THRESHOLD_RULE
        and configuration.decision_threshold is None
    ):
        raise ValueError("El modelo experimental requiere un umbral explícito.")
    model_path = configuration.model_path
    database_path = Path(database_path)
    hash_before_load = _file_sha256(model_path)
    model = load_trained_model(model_path)
    model_sha256 = _file_sha256(model_path)
    if model_sha256 != hash_before_load:
        raise RuntimeError("El artefacto del modelo cambió mientras se cargaba.")
    expected, numeric = _model_input_schema(model)
    validated = _validate_records(records, expected, numeric)
    initialize_database(database_path)

    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    run_id = create_analysis_run(
        database_path,
        source=source,
        model_reference=str(model_path),
        model_id=configuration.model_id,
        decision_rule=configuration.decision_rule,
        decision_threshold=configuration.decision_threshold,
        model_sha256=model_sha256,
        started_at=started_at,
    )
    try:
        prediction_output: list[
            tuple[np.ndarray, list[float | None]]
        ] = []

        def predict_records() -> None:
            classifier = model.named_steps["classifier"]
            model_scores: list[float | None] = [None] * len(validated)
            if configuration.decision_rule == THRESHOLD_RULE:
                classes = list(getattr(classifier, "classes_", ()))
                if 0 not in classes or 1 not in classes:
                    raise RuntimeError(
                        "El modelo experimental debe exponer las clases 0 y 1."
                    )
                probabilities = np.asarray(model.predict_proba(validated), dtype=float)
                if probabilities.shape != (len(validated), len(classes)):
                    raise RuntimeError(
                        "El Pipeline devolvió una matriz predict_proba incompatible."
                    )
                attack_scores = probabilities[:, classes.index(1)]
                if (
                    not np.isfinite(attack_scores).all()
                    or ((attack_scores < 0) | (attack_scores > 1)).any()
                ):
                    raise RuntimeError(
                        "El Pipeline devolvió probabilidades de ataque inválidas."
                    )
                model_scores = [float(value) for value in attack_scores]
                threshold = configuration.decision_threshold
                if threshold is None:
                    raise RuntimeError(
                        "El modelo experimental no tiene un umbral configurado."
                    )
                raw = (attack_scores >= threshold).astype("int64")
            else:
                raw = np.asarray(model.predict(validated)).reshape(-1)
                if hasattr(model, "predict_proba") and hasattr(classifier, "classes_"):
                    classes = list(classifier.classes_)
                    if 1 in classes:
                        probabilities = np.asarray(model.predict_proba(validated))
                        if probabilities.shape != (len(validated), len(classes)):
                            raise RuntimeError(
                                "El Pipeline devolvió una matriz predict_proba incompatible."
                            )
                        attack_scores = probabilities[:, classes.index(1)]
                        if (
                            not np.isfinite(attack_scores).all()
                            or ((attack_scores < 0) | (attack_scores > 1)).any()
                        ):
                            raise RuntimeError(
                                "El Pipeline devolvió probabilidades de ataque inválidas."
                            )
                        model_scores = [float(value) for value in attack_scores]
            prediction_output.append((raw, model_scores))

        resources = measure_operation(
            predict_records,
            sample_size=len(validated),
        )
        raw_predictions, scores = prediction_output[0]
        if len(raw_predictions) != len(record_ids):
            raise RuntimeError(
                "El Pipeline devolvió un número de predicciones distinto al "
                "número de registros."
            )
        if not np.isin(raw_predictions, (0, 1)).all():
            raise RuntimeError(
                "El Pipeline devolvió clases distintas de 0 (normal) y 1 (ataque)."
            )
        predictions = tuple(int(value) for value in raw_predictions)

        alerts_created = complete_analysis_run(
            database_path,
            run_id,
            record_ids=record_ids,
            predictions=predictions,
            scores=scores,
        )
    except Exception as error:
        try:
            fail_analysis_run(database_path, run_id, f"{type(error).__name__}: {error}")
        except Exception as persistence_error:
            raise persistence_error from error
        raise

    return InferenceRunResult(
        run_id=run_id,
        records_processed=len(predictions),
        alerts_created=alerts_created,
        predictions=predictions,
        attack_scores=tuple(scores),
        database_path=database_path,
        resource_measurement=resources,
        model_id=configuration.model_id,
        decision_rule=configuration.decision_rule,
        decision_threshold=configuration.decision_threshold,
        model_sha256=model_sha256,
        model_reference=str(model_path),
    )
