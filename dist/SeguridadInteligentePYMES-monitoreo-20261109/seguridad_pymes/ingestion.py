"""Carga, validación y preparación de los CSV oficiales de UNSW-NB15.

Las columnas de características se descubren a partir del encabezado presente
en ambos archivos; no se mantiene una lista de columnas supuesta.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


DEFAULT_TRAIN_PATH = Path("data/raw/UNSW_NB15_training-set.csv")
DEFAULT_TEST_PATH = Path("data/raw/UNSW_NB15_testing-set.csv")
TARGET_COLUMN = "label"
EXCLUDED_PREDICTOR_COLUMNS = frozenset({"id", "attack_cat", TARGET_COLUMN})


class DatasetValidationError(ValueError):
    """Indica que un CSV no cumple el contrato mínimo de datos esperado."""


@dataclass(frozen=True)
class DataQualityReport:
    """Resumen auditable del tratamiento realizado a una partición."""

    source: Path
    rows_read: int
    rows_kept: int
    dropped_by_reason: dict[str, int]
    categorical_unique_values: dict[str, int]
    unseen_test_categories: dict[str, int]

    @property
    def rows_dropped(self) -> int:
        return sum(self.dropped_by_reason.values())


@dataclass(frozen=True)
class LoadedDataset:
    """Particiones validadas sin transformar, listas para el ajuste del pipeline."""

    X_train: pd.DataFrame
    y_train: pd.Series
    X_test: pd.DataFrame
    y_test: pd.Series
    numeric_columns: tuple[str, ...]
    categorical_columns: tuple[str, ...]
    excluded_columns: tuple[str, ...]
    train_report: DataQualityReport
    test_report: DataQualityReport


@dataclass(frozen=True)
class TrainingDataset:
    """Partición de entrenamiento ya validada, sin abrir el archivo de prueba."""

    X_train: pd.DataFrame
    y_train: pd.Series
    numeric_columns: tuple[str, ...]
    categorical_columns: tuple[str, ...]
    excluded_columns: tuple[str, ...]
    train_report: DataQualityReport


@dataclass(frozen=True)
class TestDataset:
    """Partición oficial de prueba validada contra el esquema del Pipeline."""

    X_test: pd.DataFrame
    y_test: pd.Series
    test_report: DataQualityReport


@dataclass(frozen=True)
class PreparedDataset:
    """Particiones transformadas y pipeline ajustado solo con entrenamiento."""

    X_train: Any
    y_train: pd.Series
    X_test: Any
    y_test: pd.Series
    preprocessing_pipeline: Pipeline
    feature_names: tuple[str, ...]
    train_report: DataQualityReport
    test_report: DataQualityReport


def _read_header(path: Path) -> tuple[str, ...]:
    if not path.is_file():
        raise FileNotFoundError(f"No se encontró el archivo de datos: {path}")

    try:
        with path.open("r", encoding="utf-8-sig", newline="") as csv_file:
            header = next(csv.reader(csv_file), None)
    except (OSError, UnicodeError, csv.Error) as error:
        raise DatasetValidationError(
            f"No se pudo leer el encabezado CSV de {path}: {error}"
        ) from error

    if not header or any(not name.strip() for name in header):
        raise DatasetValidationError(f"El CSV {path} tiene un encabezado vacío.")
    if len(header) != len(set(header)):
        raise DatasetValidationError(f"El CSV {path} contiene nombres de columna duplicados.")
    if any(name != name.strip() for name in header):
        raise DatasetValidationError(
            f"El CSV {path} contiene espacios alrededor de nombres de columna."
        )
    return tuple(header)


def _read_csv(path: Path, expected_header: tuple[str, ...]) -> pd.DataFrame:
    try:
        frame = pd.read_csv(path, dtype="string", encoding="utf-8-sig", low_memory=False)
    except (OSError, UnicodeError, pd.errors.ParserError, pd.errors.EmptyDataError) as error:
        raise DatasetValidationError(f"No se pudo leer el CSV {path}: {error}") from error

    if tuple(frame.columns) != expected_header:
        raise DatasetValidationError(
            f"Las columnas interpretadas por pandas no coinciden con el encabezado "
            f"CSV en {path}."
        )

    for column in frame.columns:
        values = frame[column].str.strip()
        frame[column] = values.mask(values.eq(""), pd.NA)
    return frame


def _find_column(columns: tuple[str, ...], requested_name: str, path: Path) -> str:
    matches = [column for column in columns if column.casefold() == requested_name.casefold()]
    if len(matches) != 1:
        raise DatasetValidationError(
            f"{path} debe contener exactamente una columna '{requested_name}'."
        )
    return matches[0]


def _clean_partition(
    frame: pd.DataFrame,
    label_column: str,
    numeric_columns: tuple[str, ...] | None = None,
) -> tuple[pd.DataFrame, pd.Series, dict[str, int], dict[str, int]]:
    rows_read = len(frame)
    dropped = {
        "duplicate_rows": 0,
        "rows_with_missing_values": 0,
        "invalid_binary_label": 0,
        "invalid_numeric_values": 0,
    }

    frame = frame.drop_duplicates(keep="first").copy()
    dropped["duplicate_rows"] = rows_read - len(frame)

    missing = frame.isna().any(axis=1)
    dropped["rows_with_missing_values"] = int(missing.sum())
    frame = frame.loc[~missing].copy()

    labels_numeric = pd.to_numeric(frame[label_column], errors="coerce")
    valid_label = labels_numeric.isin((0, 1))
    dropped["invalid_binary_label"] = int((~valid_label).sum())
    frame = frame.loc[valid_label].copy()
    labels = labels_numeric.loc[valid_label].astype("int64").rename(label_column)

    excluded = {
        column
        for column in frame.columns
        if column.casefold() in EXCLUDED_PREDICTOR_COLUMNS
    }
    feature_columns = tuple(column for column in frame.columns if column not in excluded)

    if numeric_columns is None:
        detected_numeric: list[str] = []
        for column in feature_columns:
            parsed = pd.to_numeric(frame[column], errors="coerce")
            if parsed.notna().all() and parsed.notna().any():
                detected_numeric.append(column)
        numeric_columns = tuple(detected_numeric)

    numeric_set = set(numeric_columns)
    invalid_numeric = pd.Series(False, index=frame.index)
    for column in numeric_columns:
        parsed = pd.to_numeric(frame[column], errors="coerce")
        finite = pd.Series(
            np.isfinite(parsed.to_numpy(dtype=float, na_value=np.nan)),
            index=frame.index,
        )
        invalid_numeric |= parsed.isna() | ~finite
        frame[column] = parsed

    dropped["invalid_numeric_values"] = int(invalid_numeric.sum())
    frame = frame.loc[~invalid_numeric].copy()
    labels = labels.loc[frame.index]

    categorical_columns = tuple(
        column for column in feature_columns if column not in numeric_set
    )
    for column in categorical_columns:
        frame[column] = frame[column].astype("string")

    features = frame.loc[:, feature_columns].copy()
    category_counts = {
        column: int(features[column].nunique(dropna=True))
        for column in categorical_columns
    }
    return features, labels, dropped, category_counts


def _infer_numeric_columns(
    frame: pd.DataFrame, feature_columns: tuple[str, ...]
) -> tuple[str, ...]:
    detected_numeric: list[str] = []
    for column in feature_columns:
        values = pd.to_numeric(frame[column], errors="coerce")
        if values.notna().all() and values.notna().any():
            detected_numeric.append(column)
    return tuple(detected_numeric)


def load_unsw_training(
    train_path: str | Path = DEFAULT_TRAIN_PATH,
) -> TrainingDataset:
    """Valida únicamente el CSV oficial de entrenamiento.

    Esta función no abre ni consulta el archivo de prueba, por lo que puede
    usarse para seleccionar hiperparámetros sin exponer el holdout.
    """

    train_path = Path(train_path)
    train_header = _read_header(train_path)
    label_column = _find_column(train_header, TARGET_COLUMN, train_path)
    raw_train = _read_csv(train_path, train_header)

    train_deduplicated = raw_train.drop_duplicates(keep="first")
    train_for_detection = train_deduplicated.loc[
        ~train_deduplicated.isna().any(axis=1)
    ].copy()
    train_labels = pd.to_numeric(
        train_for_detection[label_column], errors="coerce"
    )
    train_for_detection = train_for_detection.loc[
        train_labels.isin((0, 1))
    ].copy()
    feature_columns = tuple(
        column
        for column in train_header
        if column.casefold() not in EXCLUDED_PREDICTOR_COLUMNS
    )
    numeric_columns = _infer_numeric_columns(train_for_detection, feature_columns)

    X_train, y_train, dropped, categories = _clean_partition(
        raw_train, label_column, numeric_columns
    )
    if len(X_train) == 0:
        raise DatasetValidationError(
            "No quedan filas válidas en entrenamiento después de la validación: "
            f"{dropped}."
        )
    if not X_train.columns.size:
        raise DatasetValidationError("No se encontraron columnas predictoras válidas.")

    categorical_columns = tuple(
        column for column in X_train.columns if column not in numeric_columns
    )
    report = DataQualityReport(
        source=train_path,
        rows_read=len(raw_train),
        rows_kept=len(X_train),
        dropped_by_reason=dropped,
        categorical_unique_values=categories,
        unseen_test_categories={},
    )
    excluded_columns = tuple(
        column for column in train_header if column not in X_train.columns
    )
    return TrainingDataset(
        X_train=X_train,
        y_train=y_train,
        numeric_columns=numeric_columns,
        categorical_columns=categorical_columns,
        excluded_columns=excluded_columns,
        train_report=report,
    )


def load_unsw_test_for_model(
    test_path: str | Path,
    expected_features: tuple[str, ...],
    numeric_features: tuple[str, ...],
) -> TestDataset:
    """Carga solo el CSV de prueba y valida columnas según un Pipeline entrenado."""

    test_path = Path(test_path)
    if not expected_features:
        raise DatasetValidationError("El Pipeline no declara características de entrada.")
    if any(
        column.casefold() in EXCLUDED_PREDICTOR_COLUMNS
        for column in expected_features
    ):
        raise DatasetValidationError(
            "El esquema del Pipeline incluye una columna objetivo o excluida "
            "(`label`, `id` o `attack_cat`)."
        )
    if len(expected_features) != len(set(expected_features)):
        raise DatasetValidationError(
            "El esquema del Pipeline contiene características duplicadas."
        )
    if not set(numeric_features).issubset(expected_features):
        raise DatasetValidationError(
            "El esquema numérico no es un subconjunto de las características."
        )

    test_header = _read_header(test_path)
    label_column = _find_column(test_header, TARGET_COLUMN, test_path)
    missing_features = [column for column in expected_features if column not in test_header]
    if missing_features:
        raise DatasetValidationError(
            f"El CSV de prueba no contiene características requeridas por el Pipeline: "
            f"{missing_features}."
        )
    raw_test = _read_csv(test_path, test_header)
    duplicate_mask = raw_test.duplicated(keep="first")
    dropped = {
        "duplicate_rows": int(duplicate_mask.sum()),
        "rows_with_missing_values": 0,
        "invalid_binary_label": 0,
        "invalid_numeric_values": 0,
    }
    frame = raw_test.loc[~duplicate_mask, [*expected_features, label_column]].copy()

    missing_mask = frame.isna().any(axis=1)
    dropped["rows_with_missing_values"] = int(missing_mask.sum())
    frame = frame.loc[~missing_mask].copy()
    labels_numeric = pd.to_numeric(frame[label_column], errors="coerce")
    valid_label = labels_numeric.isin((0, 1))
    dropped["invalid_binary_label"] = int((~valid_label).sum())
    frame = frame.loc[valid_label].copy()
    labels = labels_numeric.loc[valid_label].astype("int64").rename(label_column)

    numeric_set = set(numeric_features)
    invalid_numeric = pd.Series(False, index=frame.index)
    for column in numeric_features:
        parsed = pd.to_numeric(frame[column], errors="coerce")
        finite = pd.Series(
            np.isfinite(parsed.to_numpy(dtype=float, na_value=np.nan)),
            index=frame.index,
        )
        invalid_numeric |= parsed.isna() | ~finite
        frame[column] = parsed

    dropped["invalid_numeric_values"] = int(invalid_numeric.sum())
    frame = frame.loc[~invalid_numeric].copy()
    labels = labels.loc[frame.index]
    categorical_features = tuple(
        column for column in expected_features if column not in numeric_set
    )
    for column in categorical_features:
        frame[column] = frame[column].astype("string")

    X_test = frame.loc[:, expected_features].copy()
    report = DataQualityReport(
        source=test_path,
        rows_read=len(raw_test),
        rows_kept=len(X_test),
        dropped_by_reason=dropped,
        categorical_unique_values={
            column: int(X_test[column].nunique(dropna=True))
            for column in categorical_features
        },
        unseen_test_categories={},
    )
    if X_test.empty:
        raise DatasetValidationError(
            f"No quedan filas válidas en prueba: {dropped}."
        )
    return TestDataset(X_test=X_test, y_test=labels, test_report=report)


def load_unsw_nb15(
    train_path: str | Path = DEFAULT_TRAIN_PATH,
    test_path: str | Path = DEFAULT_TEST_PATH,
) -> LoadedDataset:
    """Lee y valida los archivos oficiales, descubriendo su esquema en ejecución.

    Los dos archivos deben tener el mismo encabezado y una columna binaria
    ``label``. Las columnas ``id`` y ``attack_cat``, si existen, se excluyen de
    los predictores. No se ajusta ninguna transformación en esta función.
    """

    training = load_unsw_training(train_path)
    train_path = Path(train_path)
    test_path = Path(test_path)
    train_header = _read_header(train_path)
    test_header = _read_header(test_path)
    if train_header != test_header:
        raise DatasetValidationError(
            "Los CSV de entrenamiento y prueba no tienen los mismos nombres y "
            "orden de columnas."
        )

    label_column = _find_column(train_header, TARGET_COLUMN, train_path)
    raw_test = _read_csv(test_path, test_header)

    numeric_columns = training.numeric_columns
    X_train = training.X_train
    y_train = training.y_train
    X_test, y_test, test_dropped, test_categories = _clean_partition(
        raw_test, label_column, numeric_columns
    )

    if len(X_test) == 0:
        raise DatasetValidationError(
            "No quedan filas válidas en prueba después de la "
            f"validación: {test_dropped}."
        )
    if not X_train.columns.equals(X_test.columns):
        raise DatasetValidationError(
            "Las características de entrenamiento y prueba no coinciden."
        )
    if not X_train.columns.size:
        raise DatasetValidationError("No se encontraron columnas predictoras válidas.")

    categorical_columns = training.categorical_columns
    unseen_categories = {
        column: len(set(X_test[column].dropna()) - set(X_train[column].dropna()))
        for column in categorical_columns
    }
    train_report = training.train_report
    test_report = DataQualityReport(
        source=test_path,
        rows_read=len(raw_test),
        rows_kept=len(X_test),
        dropped_by_reason=test_dropped,
        categorical_unique_values=test_categories,
        unseen_test_categories=unseen_categories,
    )

    return LoadedDataset(
        X_train=X_train,
        y_train=y_train,
        X_test=X_test,
        y_test=y_test,
        numeric_columns=numeric_columns,
        categorical_columns=categorical_columns,
        excluded_columns=training.excluded_columns,
        train_report=train_report,
        test_report=test_report,
    )


def build_preprocessing_pipeline(dataset: LoadedDataset) -> Pipeline:
    """Construye un pipeline sin ajustarlo; el ajuste debe usar solo X_train."""

    transformers: list[tuple[str, Any, list[str]]] = []
    if dataset.numeric_columns:
        transformers.append(
            ("numeric", StandardScaler(), list(dataset.numeric_columns))
        )
    if dataset.categorical_columns:
        transformers.append(
            (
                "categorical",
                OneHotEncoder(handle_unknown="ignore"),
                list(dataset.categorical_columns),
            )
        )
    if not transformers:
        raise DatasetValidationError("No hay características utilizables para procesar.")

    return Pipeline(
        steps=[
            (
                "features",
                ColumnTransformer(
                    transformers=transformers,
                    remainder="drop",
                    verbose_feature_names_out=True,
                ),
            )
        ]
    )


def prepare_unsw_nb15(
    train_path: str | Path = DEFAULT_TRAIN_PATH,
    test_path: str | Path = DEFAULT_TEST_PATH,
) -> PreparedDataset:
    """Carga los splits y ajusta las transformaciones únicamente con entrenamiento."""

    loaded = load_unsw_nb15(train_path, test_path)
    pipeline = build_preprocessing_pipeline(loaded)
    X_train = pipeline.fit_transform(loaded.X_train)
    X_test = pipeline.transform(loaded.X_test)
    feature_names = tuple(
        pipeline.named_steps["features"].get_feature_names_out().tolist()
    )
    return PreparedDataset(
        X_train=X_train,
        y_train=loaded.y_train,
        X_test=X_test,
        y_test=loaded.y_test,
        preprocessing_pipeline=pipeline,
        feature_names=feature_names,
        train_report=loaded.train_report,
        test_report=loaded.test_report,
    )
