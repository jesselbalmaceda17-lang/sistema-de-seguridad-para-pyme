"""Entrenamiento reproducible de Random Forest para UNSW-NB15."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline

from seguridad_pymes.ingestion import (
    DEFAULT_TRAIN_PATH,
    TrainingDataset,
    build_preprocessing_pipeline,
    load_unsw_training,
)


DEFAULT_MODEL_PATH = Path("models/unsw_nb15_random_forest.joblib")
DEFAULT_PILOT_MODEL_PATH = Path("models/unsw_nb15_random_forest_pilot.joblib")
THRESHOLD_STUDY_MODEL_PATH = Path(
    "data/processed/threshold_study/threshold_study_random_forest.joblib"
)
DEFAULT_RANDOM_STATE = 42
PARAMETER_DISTRIBUTIONS = {
    "classifier__n_estimators": [100, 160],
    "classifier__max_depth": [None, 24],
    "classifier__min_samples_leaf": [1, 2],
    "classifier__max_features": ["sqrt"],
}
PILOT_PARAMETER_DISTRIBUTIONS = {
    "classifier__n_estimators": [50, 80],
    "classifier__max_depth": [16, 24],
    "classifier__min_samples_leaf": [2],
    "classifier__max_features": ["sqrt"],
}
FINAL_FIXED_PARAMETERS = {
    "classifier__n_estimators": 80,
    "classifier__max_depth": 24,
    "classifier__min_samples_leaf": 2,
    "classifier__max_features": "sqrt",
}
PILOT_SELECTION_PROVENANCE = (
    "Hyperparameters were selected by cross-validation on a stratified pilot "
    "sample of the official training split."
)


@dataclass(frozen=True)
class TrainingResult:
    """Resumen de entrenamiento y selección de hiperparámetros."""

    model_path: Path
    metadata_path: Path
    best_params: dict[str, Any]
    best_cv_f1: float | None
    cv_splits: int | None
    training_rows: int
    training_class_counts: dict[int, int]
    input_features: tuple[str, ...]
    transformed_features: tuple[str, ...]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_training_data(dataset: TrainingDataset, cv_splits: int) -> None:
    if cv_splits < 2:
        raise ValueError("cv_splits debe ser al menos 2.")

    classes = set(dataset.y_train.unique().tolist())
    if classes != {0, 1}:
        raise ValueError(
            "El entrenamiento debe contener ambas clases binarias 0 (normal) y "
            f"1 (ataque); clases encontradas: {sorted(classes)}."
        )

    counts = dataset.y_train.value_counts()
    smallest_class = int(counts.min())
    if smallest_class < cv_splits:
        raise ValueError(
            "Cada clase debe tener al menos tantas filas como particiones de "
            f"validación (mínimo por clase={smallest_class}, cv_splits={cv_splits})."
        )


def _build_estimator(dataset: TrainingDataset, random_state: int) -> Pipeline:
    preprocessing = build_preprocessing_pipeline(dataset).named_steps["features"]
    return Pipeline(
        steps=[
            ("preprocessing", preprocessing),
            (
                "classifier",
                RandomForestClassifier(
                    random_state=random_state,
                    n_jobs=1,
                ),
            ),
        ]
    )


def _sample_training_dataset(
    dataset: TrainingDataset,
    sample_rows: int | None,
    random_state: int,
) -> tuple[TrainingDataset, dict[int, int]]:
    full_class_counts = {
        int(label): int(count)
        for label, count in dataset.y_train.value_counts().sort_index().items()
    }
    if sample_rows is None or sample_rows == len(dataset.X_train):
        return dataset, full_class_counts
    if sample_rows < 1 or sample_rows > len(dataset.X_train):
        raise ValueError(
            "sample_rows debe estar entre 1 y la cantidad de filas válidas "
            f"({len(dataset.X_train)})."
        )

    X_sample, _, y_sample, _ = train_test_split(
        dataset.X_train,
        dataset.y_train,
        train_size=sample_rows,
        random_state=random_state,
        stratify=dataset.y_train,
    )
    sampled_dataset = TrainingDataset(
        X_train=X_sample,
        y_train=y_sample,
        numeric_columns=dataset.numeric_columns,
        categorical_columns=dataset.categorical_columns,
        excluded_columns=dataset.excluded_columns,
        train_report=dataset.train_report,
    )
    sampled_class_counts = {
        int(label): int(count)
        for label, count in y_sample.value_counts().sort_index().items()
    }
    return sampled_dataset, sampled_class_counts


def train_random_forest(
    train_path: str | Path = DEFAULT_TRAIN_PATH,
    model_path: str | Path | None = None,
    *,
    random_state: int = DEFAULT_RANDOM_STATE,
    cv_splits: int | None = None,
    search_iterations: int | None = None,
    sample_rows: int | None = None,
    profile: str = "default",
) -> TrainingResult:
    """Ajusta un Pipeline usando exclusivamente datos del conjunto de entrenamiento.

    Los perfiles default y pilot seleccionan parámetros mediante CV estratificada;
    final-fixed ajusta directamente los parámetros seleccionados en el piloto.
    Ningún perfil recibe ni abre la ruta del conjunto oficial de prueba.
    """

    if profile not in {"default", "pilot", "final-fixed"}:
        raise ValueError("profile debe ser 'default', 'pilot' o 'final-fixed'.")
    if profile == "pilot":
        if cv_splits not in (None, 2) or search_iterations not in (None, 2):
            raise ValueError(
                "El perfil pilot requiere cv_splits=2 y search_iterations=2."
            )
        cv_splits = 2 if cv_splits is None else cv_splits
        search_iterations = 2 if search_iterations is None else search_iterations
        if sample_rows is None:
            sample_rows = 20_000
        parameter_distributions = PILOT_PARAMETER_DISTRIBUTIONS
        default_model_path = DEFAULT_PILOT_MODEL_PATH
    elif profile == "final-fixed":
        if cv_splits is not None or search_iterations is not None or sample_rows is not None:
            raise ValueError(
                "El perfil final-fixed usa todos los datos y no acepta "
                "cv_splits, search_iterations ni sample_rows."
            )
        if random_state != DEFAULT_RANDOM_STATE:
            raise ValueError("El perfil final-fixed requiere random_state=42.")
        cv_splits = None
        search_iterations = None
        parameter_distributions = {
            key: [value] for key, value in FINAL_FIXED_PARAMETERS.items()
        }
        default_model_path = DEFAULT_MODEL_PATH
    else:
        if sample_rows is not None:
            raise ValueError("--sample-rows requiere --profile pilot.")
        cv_splits = 3 if cv_splits is None else cv_splits
        search_iterations = 4 if search_iterations is None else search_iterations
        parameter_distributions = PARAMETER_DISTRIBUTIONS
        default_model_path = DEFAULT_MODEL_PATH

    train_path = Path(train_path)
    model_path = Path(model_path) if model_path is not None else default_model_path
    if profile == "pilot" and model_path.name != DEFAULT_PILOT_MODEL_PATH.name:
        raise ValueError(
            "El perfil pilot debe guardar el modelo con el nombre "
            f"{DEFAULT_PILOT_MODEL_PATH.name} para proteger el modelo definitivo."
        )
    if profile == "final-fixed" and model_path.name != DEFAULT_MODEL_PATH.name:
        raise ValueError(
            "El perfil final-fixed debe guardar el modelo con el nombre "
            f"{DEFAULT_MODEL_PATH.name}."
        )
    if search_iterations is not None and search_iterations < 1:
        raise ValueError("search_iterations debe ser al menos 1.")
    metadata_path = model_path.with_suffix(model_path.suffix + ".metadata.json")
    existing_artifacts = [
        path for path in (model_path, metadata_path) if path.exists()
    ]
    if existing_artifacts:
        raise FileExistsError(
            "El entrenamiento no sobrescribe artefactos existentes: "
            + ", ".join(str(path) for path in existing_artifacts)
        )

    dataset = load_unsw_training(train_path)
    valid_rows = len(dataset.X_train)
    validated_class_counts = {
        int(label): int(count)
        for label, count in dataset.y_train.value_counts().sort_index().items()
    }

    if sample_rows is not None and sample_rows != valid_rows:
        if sample_rows < 1 or sample_rows > valid_rows:
            raise ValueError(
                "sample_rows debe estar entre 1 y la cantidad de filas válidas "
                f"({valid_rows})."
            )
        if sample_rows < 2:
            raise ValueError("La muestra debe incluir al menos dos registros.")
    if profile == "final-fixed":
        sampled_class_counts = validated_class_counts
        _validate_training_data(dataset, 2)
        best_pipeline = _build_estimator(dataset, random_state).set_params(
            **FINAL_FIXED_PARAMETERS
        )
        tested_parameters: list[dict[str, Any]] = []
        best_params = dict(FINAL_FIXED_PARAMETERS)
        best_cv_f1 = None
        selection = "fixed parameters selected using pilot cross-validation"
        selection_scoring = None
        selection_cv = None
        timing_scope = "Pipeline.fit on all validated training rows"
        started = time.perf_counter()
        best_pipeline.fit(dataset.X_train, dataset.y_train)
        training_time_seconds = time.perf_counter() - started
    else:
        _validate_training_data(dataset, cv_splits)
        dataset, sampled_class_counts = _sample_training_dataset(
            dataset,
            sample_rows,
            random_state,
        )
        _validate_training_data(dataset, cv_splits)

        total_candidates = math.prod(
            len(values) for values in parameter_distributions.values()
        )
        if search_iterations > total_candidates:
            raise ValueError(
                f"search_iterations no puede superar las {total_candidates} "
                "combinaciones definidas."
            )

        cv = StratifiedKFold(
            n_splits=cv_splits,
            shuffle=True,
            random_state=random_state,
        )
        search = RandomizedSearchCV(
            estimator=_build_estimator(dataset, random_state),
            param_distributions=parameter_distributions,
            n_iter=search_iterations,
            scoring="f1",
            cv=cv,
            refit=True,
            random_state=random_state,
            n_jobs=1,
            pre_dispatch=1,
            error_score="raise",
            return_train_score=False,
        )
        started = time.perf_counter()
        search.fit(dataset.X_train, dataset.y_train)
        training_time_seconds = time.perf_counter() - started

        best_pipeline = search.best_estimator_
        tested_parameters = [
            {
                "parameters": parameters,
                "mean_cv_f1": float(score),
            }
            for parameters, score in zip(
                search.cv_results_["params"],
                search.cv_results_["mean_test_score"],
                strict=True,
            )
        ]
        best_params = dict(search.best_params_)
        best_cv_f1 = float(search.best_score_)
        selection = "RandomizedSearchCV"
        selection_scoring = "f1 (positive class 1: attack)"
        selection_cv = {
            "strategy": "StratifiedKFold",
            "n_splits": cv_splits,
            "shuffle": True,
            "random_state": random_state,
        }
        timing_scope = "RandomizedSearchCV.fit, including CV and refit"

    transformed_features = tuple(
        best_pipeline.named_steps["preprocessing"]
        .get_feature_names_out()
        .tolist()
    )
    model_path.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(best_pipeline, model_path)
    class_counts = sampled_class_counts
    hyperparameter_selection = None
    if profile == "final-fixed":
        hyperparameter_selection = {
            "method": "StratifiedKFold cross-validation",
            "source_dataset": "stratified pilot sample from official training split",
            "sample_rows": 20_000,
            "random_state": DEFAULT_RANDOM_STATE,
            "n_splits": 2,
            "scoring": "f1 (positive class 1: attack)",
            "mean_cv_f1": 0.9619155387415723,
            "selected_parameters": {
                "n_estimators": 80,
                "max_depth": 24,
                "min_samples_leaf": 2,
                "max_features": "sqrt",
            },
            "provenance": PILOT_SELECTION_PROVENANCE,
        }
    metadata = {
        "dataset": {
            "name": "UNSW-NB15",
            "training_file": train_path.name,
            "training_file_sha256": _sha256(train_path),
            "test_file_used": False,
        },
        "target": "label",
        "class_meaning": {"0": "normal", "1": "attack"},
        "training": {
            "profile": profile,
            "rows_original": int(dataset.train_report.rows_read),
            "rows_valid_after_cleaning": int(valid_rows),
            "rows_selected_for_training": int(len(dataset.X_train)),
            "rows_after_validation": int(valid_rows),
            "class_counts": {str(key): value for key, value in class_counts.items()},
            "class_counts_selected": {
                str(key): value for key, value in class_counts.items()
            },
            "class_counts_validated": {
                str(key): value for key, value in validated_class_counts.items()
            },
            "data_quality": {
                "rows_read": dataset.train_report.rows_read,
                "rows_kept": dataset.train_report.rows_kept,
                "dropped_by_reason": dataset.train_report.dropped_by_reason,
                "categorical_unique_values": (
                    dataset.train_report.categorical_unique_values
                ),
            },
            "random_state": random_state,
            "sample_random_state": random_state if sample_rows is not None else None,
            "training_time_seconds": training_time_seconds,
            "training_time_scope": timing_scope,
            "selection": selection,
            "hyperparameter_selection": hyperparameter_selection,
            "scoring": selection_scoring,
            "cv": selection_cv,
            "search_iterations": search_iterations,
            "candidate_parameters": parameter_distributions,
            "parameters_tested": tested_parameters,
            "best_parameters": best_params,
            "best_mean_cv_f1": best_cv_f1,
            "classifier_parameters": (
                best_pipeline.named_steps["classifier"].get_params(deep=False)
            ),
            "preprocessing": {
                "numeric_transformer": "StandardScaler",
                "categorical_transformer": "OneHotEncoder",
                "unknown_category_policy": "ignore",
            },
        },
        "features": {
            "target_and_excluded": ["label", "id", "attack_cat"],
            "input_predictors": list(dataset.X_train.columns),
            "numeric": list(dataset.numeric_columns),
            "categorical": list(dataset.categorical_columns),
            "transformed": list(transformed_features),
        },
        "libraries": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "pandas": pd.__version__,
            "numpy": np.__version__,
            "joblib": joblib.__version__,
        },
        "artifact": {
            "pipeline_file": model_path.name,
            "pipeline_steps": list(best_pipeline.named_steps),
        },
    }
    metadata_path.write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    return TrainingResult(
        model_path=model_path,
        metadata_path=metadata_path,
        best_params=best_params,
        best_cv_f1=best_cv_f1,
        cv_splits=cv_splits,
        training_rows=len(dataset.X_train),
        training_class_counts=class_counts,
        input_features=tuple(dataset.X_train.columns.tolist()),
        transformed_features=transformed_features,
    )


def load_trained_model(model_path: str | Path = DEFAULT_MODEL_PATH) -> Pipeline:
    """Carga el Pipeline completo desde un artefacto local de confianza.

    joblib puede ejecutar código al deserializar; no cargue archivos recibidos de
    fuentes no confiables.
    """

    model_path = Path(model_path)
    model = joblib.load(model_path)
    if not isinstance(model, Pipeline):
        raise TypeError(f"El artefacto {model_path} no contiene un sklearn Pipeline.")
    if not {"preprocessing", "classifier"}.issubset(model.named_steps):
        raise TypeError(
            f"El Pipeline {model_path} no contiene los pasos esperados "
            "'preprocessing' y 'classifier'."
        )
    return model


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Entrena Random Forest con el split oficial de entrenamiento UNSW-NB15."
    )
    parser.add_argument("--train", type=Path, default=DEFAULT_TRAIN_PATH)
    parser.add_argument("--model", type=Path)
    parser.add_argument(
        "--profile",
        choices=("default", "pilot", "final-fixed"),
        default="default",
        help="Select default search, pilot search, or fixed final parameters.",
    )
    parser.add_argument(
        "--sample-rows",
        type=int,
        help="Stratified sample size; requires --profile pilot (default: 20000).",
    )
    parser.add_argument("--random-state", type=int, default=DEFAULT_RANDOM_STATE)
    parser.add_argument("--cv-splits", type=int)
    parser.add_argument("--search-iterations", type=int)
    args = parser.parse_args()

    result = train_random_forest(
        train_path=args.train,
        model_path=args.model,
        random_state=args.random_state,
        cv_splits=args.cv_splits,
        search_iterations=args.search_iterations,
        sample_rows=args.sample_rows,
        profile=args.profile,
    )
    print(f"Modelo guardado: {result.model_path}")
    print(f"Metadatos: {result.metadata_path}")
    print(f"Filas de entrenamiento: {result.training_rows}")
    print(f"Conteo por clase: {result.training_class_counts}")
    if result.best_cv_f1 is not None:
        print(f"Mejor F1 medio de validación CV: {result.best_cv_f1:.6f}")
    else:
        print("El modelo final usa hiperparámetros seleccionados en el piloto.")
    print(f"Mejores parámetros: {result.best_params}")
    print("El conjunto oficial de prueba no se leyó ni se usó durante el entrenamiento.")


if __name__ == "__main__":
    main()
