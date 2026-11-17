"""Panel Streamlit para análisis por lotes, alertas e historial SQLite."""

from __future__ import annotations

import csv
import io
import json
import os
import pickle
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from seguridad_pymes.database import (
    DEFAULT_DATABASE_PATH,
    PersistenceError,
    REVIEW_STATES,
    initialize_database,
    list_alerts,
    list_analysis_runs,
    update_alert_review_state,
)
from seguridad_pymes.inference import (
    PRODUCTION_MODEL_ID,
    PRODUCTION_MODEL_LABEL,
    THRESHOLD_STUDY_MODEL_ID,
    THRESHOLD_STUDY_MODEL_LABEL,
    InferenceRunResult,
    infer_model_configuration,
    model_configuration,
    run_model_analysis,
    _model_input_schema,
)
from seguridad_pymes.training import DEFAULT_MODEL_PATH, load_trained_model


MAX_UPLOAD_BYTES = 100 * 1024 * 1024
OPTIONAL_METADATA_COLUMNS = frozenset({"id", "label", "attack_cat"})
MODEL_LABELS = {
    PRODUCTION_MODEL_ID: PRODUCTION_MODEL_LABEL,
    THRESHOLD_STUDY_MODEL_ID: THRESHOLD_STUDY_MODEL_LABEL,
}
REVIEW_OPTIONS = {
    "Pendiente de revisión": "pending",
    "Confirmada (revisión manual)": "confirmed",
    "Falso positivo": "false_positive",
}
REVIEW_LABELS = {
    "pending": "Pendiente de revisión",
    "confirmed": "Confirmada (revisión manual)",
    "false_positive": "Falso positivo",
}
SCORE_REPORT_COLUMN = "probabilidad_ataque"
SCORE_DISPLAY_LABEL = "Score del modelo (clase 1)"
SCORE_DISCLAIMER = (
    "El score del modelo (clase 1) no es necesariamente una probabilidad "
    "calibrada ni confirma un ataque."
)
RUN_HISTORY_LIMIT = 100
ALERT_HISTORY_LIMIT = 10000
SAFE_RUN_ERROR_DESCRIPTIONS = {
    "FileNotFoundError": (
        "No se encontró un archivo necesario para el análisis. Verifique que "
        "esté disponible y vuelva a intentarlo."
    ),
    "PermissionError": (
        "No fue posible acceder a un archivo o recurso necesario. Revise los "
        "permisos y vuelva a intentarlo."
    ),
    "ValueError": (
        "Los datos o la configuración no cumplen los requisitos del análisis. "
        "Revise el formato y los campos obligatorios."
    ),
    "TypeError": (
        "Los datos o la configuración tienen un formato incompatible con el análisis."
    ),
    "RuntimeError": (
        "El análisis no pudo completarse durante el procesamiento. Revise los "
        "datos y vuelva a intentarlo."
    ),
    "PersistenceError": (
        "No fue posible guardar el resultado en la base local. Revise que el "
        "archivo esté disponible y vuelva a intentarlo."
    ),
    "ImportError": (
        "No se pudo cargar un componente requerido. Revise la instalación del entorno."
    ),
    "EOFError": (
        "Un archivo necesario está incompleto o no se pudo leer."
    ),
}
GENERIC_RUN_ERROR_DESCRIPTION = (
    "La ejecución no pudo completarse. Revise los datos y la configuración, "
    "y vuelva a intentarlo."
)
ALL_FILTER_VALUE = "__all__"
MISSING_MODEL_FILTER_VALUE = "__missing_model__"


@st.cache_resource(show_spinner=False)
def _load_model(model_path: str, modified_time_ns: int):
    del modified_time_ns
    try:
        return load_trained_model(model_path)
    except (pickle.UnpicklingError, OverflowError) as error:
        raise ValueError("El archivo del modelo está dañado o no tiene un formato válido.") from error


def _model_features(model: Any) -> tuple[str, ...]:
    preprocessing = model.named_steps.get("preprocessing")
    feature_names = getattr(preprocessing, "feature_names_in_", None)
    if feature_names is None or len(feature_names) == 0:
        raise ValueError("El modelo no expone las características esperadas.")
    return tuple(str(column) for column in feature_names)


def _validate_builtin_model_pair(
    production_model: Any,
    experimental_model: Any,
) -> tuple[str, ...]:
    production_schema, production_numeric = _model_input_schema(production_model)
    experimental_schema, experimental_numeric = _model_input_schema(experimental_model)
    if len(production_schema) != 42 or len(experimental_schema) != 42:
        raise ValueError("Ambos modelos deben declarar exactamente 42 características.")
    if (
        production_schema != experimental_schema
        or production_numeric != experimental_numeric
    ):
        raise ValueError(
            "Los modelos definitivo y experimental no comparten el mismo esquema "
            "de 42 características."
        )
    classifier = experimental_model.named_steps["classifier"]
    classes = list(getattr(classifier, "classes_", ()))
    if (
        not callable(getattr(experimental_model, "predict_proba", None))
        or 0 not in classes
        or 1 not in classes
    ):
        raise ValueError(
            "El modelo experimental debe exponer predict_proba y las clases 0 y 1."
        )
    return production_schema


def _format_review_state(review_state: object) -> str:
    return REVIEW_LABELS.get(str(review_state), "No disponible")


def _safe_run_error_description(error_message: object) -> str:
    if not isinstance(error_message, str) or not error_message.strip():
        return GENERIC_RUN_ERROR_DESCRIPTION
    error_type, separator, _ = error_message.partition(":")
    if not separator:
        return GENERIC_RUN_ERROR_DESCRIPTION
    return SAFE_RUN_ERROR_DESCRIPTIONS.get(
        error_type.strip(),
        GENERIC_RUN_ERROR_DESCRIPTION,
    )


def _safe_run_history_export(run_frame: pd.DataFrame) -> pd.DataFrame:
    safe_frame = run_frame.copy()
    if "error_message" in safe_frame.columns:
        safe_frame["error_message"] = safe_frame.apply(
            lambda row: (
                _safe_run_error_description(row["error_message"])
                if row.get("status") == "failed"
                else None
            ),
            axis=1,
        )
    return safe_frame


def _format_model_rule(alert: Any) -> str:
    rule = alert.get("decision_rule")
    if rule == "predict":
        return "Clasificación predeterminada"
    if rule == "predict_proba_gte":
        threshold = alert.get("decision_threshold")
        if threshold is None:
            return "Score clase 1 ≥ umbral no disponible"
        return f"Score clase 1 ≥ {float(threshold):.2f}"
    return "No disponible"


def _format_alert_model(model_id: object) -> str:
    if model_id is None or pd.isna(model_id):
        return "Modelo no disponible (ejecución histórica)"
    return MODEL_LABELS.get(str(model_id), str(model_id))


def _filter_alerts(
    alert_frame: pd.DataFrame,
    *,
    model_id: str,
    run_id: str,
    review_state: str,
    record_id_query: str,
) -> pd.DataFrame:
    filtered = alert_frame
    if model_id == MISSING_MODEL_FILTER_VALUE:
        filtered = filtered.loc[filtered["model_id"].isna()]
    elif model_id != ALL_FILTER_VALUE:
        filtered = filtered.loc[filtered["model_id"].eq(model_id)]
    if run_id != ALL_FILTER_VALUE:
        filtered = filtered.loc[filtered["run_id"].eq(run_id)]
    if review_state != ALL_FILTER_VALUE:
        filtered = filtered.loc[filtered["review_state"].eq(review_state)]
    query = record_id_query.strip().casefold()
    if query:
        filtered = filtered.loc[
            filtered["record_id"].astype(str).str.casefold().str.contains(
                query,
                regex=False,
            )
        ]
    return filtered.copy()


def _read_uploaded_csv(uploaded_file) -> tuple[pd.DataFrame, list[str]]:
    raw_bytes = uploaded_file.getvalue()
    if not raw_bytes:
        raise ValueError("El archivo está vacío.")
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        raise ValueError(
            "El archivo supera el límite de 100 MB. Divídalo en lotes más pequeños."
        )

    try:
        header_stream = io.StringIO(raw_bytes.decode("utf-8-sig"), newline="")
        header = next(csv.reader(header_stream), None)
    except (UnicodeDecodeError, csv.Error) as error:
        raise ValueError(
            "No se pudo leer el CSV como texto UTF-8. Guarde el archivo en UTF-8 "
            "y vuelva a cargarlo."
        ) from error
    if not header or any(not column.strip() for column in header):
        raise ValueError("El CSV no tiene encabezados válidos.")
    if len({column.casefold() for column in header}) != len(header):
        raise ValueError("El CSV contiene nombres de columna duplicados.")
    if any(column != column.strip() for column in header):
        raise ValueError("Quite los espacios alrededor de los nombres de columna.")

    try:
        frame = pd.read_csv(
            io.BytesIO(raw_bytes),
            dtype="string",
            encoding="utf-8-sig",
            low_memory=False,
        )
    except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeDecodeError) as error:
        raise ValueError(f"No se pudo interpretar el CSV: {error}") from error
    if tuple(frame.columns) != tuple(header):
        raise ValueError("Los encabezados del CSV no se interpretaron de forma consistente.")
    # pandas can silently consume extra leading fields as an inferred row index.
    if not isinstance(frame.index, pd.RangeIndex):
        raise ValueError(
            "La estructura del CSV contiene más campos que columnas declaradas. "
            "Corrija las filas antes de analizar."
        )
    if frame.empty:
        raise ValueError("El CSV contiene encabezados, pero no tiene registros.")

    for column in frame.columns:
        values = frame[column].str.strip()
        frame[column] = values.mask(values.eq(""), pd.NA)
    return frame, header


def _prepare_uploaded_records(
    frame: pd.DataFrame,
    headers: list[str],
    expected_features: tuple[str, ...],
    source_name: str,
) -> tuple[pd.DataFrame, list[str], list[str]]:
    metadata_columns = [
        column for column in headers if column.casefold() in OPTIONAL_METADATA_COLUMNS
    ]
    predictor_headers = [
        column for column in headers if column.casefold() not in OPTIONAL_METADATA_COLUMNS
    ]

    missing = [name for name in expected_features if name not in predictor_headers]
    unexpected = [name for name in predictor_headers if name not in expected_features]
    if missing or unexpected:
        details = []
        if missing:
            details.append(f"faltan características: {missing}")
        if unexpected:
            details.append(f"columnas no reconocidas: {unexpected}")
        raise ValueError(
            "El archivo no coincide con el esquema del modelo (" + "; ".join(details) + ")."
        )

    id_column = next(
        (column for column in headers if column.casefold() == "id"),
        None,
    )
    if id_column is not None:
        ids = frame[id_column]
        if ids.isna().any():
            raise ValueError("La columna `id` tiene valores vacíos; corríjalos antes de analizar.")
        record_ids = ids.astype(str).tolist()
        if len(set(record_ids)) != len(record_ids):
            raise ValueError(
                "La columna `id` tiene valores duplicados. Use identificadores únicos "
                "para poder referenciar alertas."
            )
    else:
        record_ids = [
            f"{Path(source_name).name}:fila-{index + 2}"
            for index in range(len(frame))
        ]

    records = frame.loc[:, expected_features].copy()
    if records.isna().any(axis=None):
        missing_counts = records.isna().sum()
        columns = missing_counts[missing_counts > 0].to_dict()
        raise ValueError(f"Hay valores faltantes en características requeridas: {columns}.")
    return records, record_ids, metadata_columns


def _prediction_report(
    run_result: InferenceRunResult,
    record_ids: list[str],
    source_name: str,
) -> pd.DataFrame:
    if len(run_result.predictions) != len(record_ids):
        raise ValueError("El resultado y los identificadores tienen longitudes distintas.")
    if len(run_result.attack_scores) != len(record_ids):
        raise ValueError("El resultado y las puntuaciones tienen longitudes distintas.")
    labels = ["Sospechoso (ataque)" if value == 1 else "Normal" for value in run_result.predictions]
    return pd.DataFrame(
        {
            "identificador_registro": record_ids,
            "clasificacion_predicha": labels,
            SCORE_REPORT_COLUMN: list(run_result.attack_scores),
            "archivo_origen": source_name,
            "id_ejecucion": run_result.run_id,
            "modelo": run_result.model_id,
            "regla_decision": run_result.decision_rule,
            "umbral_decision": run_result.decision_threshold,
        }
    )


def _prediction_report_for_display(report: pd.DataFrame) -> pd.DataFrame:
    return report.rename(columns={SCORE_REPORT_COLUMN: SCORE_DISPLAY_LABEL})


def _reset_review_state_for_selected_alert(
    alert_review_states: dict[int, str],
) -> None:
    selected_id = st.session_state.get("review_alert_id")
    review_state = alert_review_states.get(selected_id)
    if review_state is not None:
        st.session_state["review_alert_state"] = REVIEW_LABELS[review_state]


def _render_summary(report: pd.DataFrame, result: InferenceRunResult) -> None:
    suspicious = sum(value == 1 for value in result.predictions)
    normal = result.records_processed - suspicious
    first, second, third, fourth = st.columns(4)
    first.metric("Registros analizados", f"{result.records_processed:,}")
    second.metric("Normales", f"{normal:,}")
    third.metric("Sospechosos", f"{suspicious:,}")
    fourth.metric("Alertas guardadas", f"{result.alerts_created:,}")
    if result.resource_measurement is not None:
        measurement = result.resource_measurement
        st.caption(
            f"Tiempo medido de inferencia: {measurement.elapsed_seconds:.4f} s · "
            f"RSS pico: {measurement.peak_rss_mib:.1f} MiB · "
            f"incremento RSS aproximado: {measurement.peak_rss_delta_mib:.1f} MiB"
        )

    st.caption(
        f"Modelo: **{MODEL_LABELS.get(result.model_id, result.model_id)}** · "
        f"referencia: `{result.model_reference}`"
    )
    threshold_description = (
        "no aplica (clasificación predeterminada)"
        if result.decision_threshold is None
        else f"{result.decision_threshold:.2f}"
    )
    st.caption(
        f"Regla: `{result.decision_rule}` · "
        f"umbral: {threshold_description} · ejecución: `{result.run_id}`"
    )
    st.caption(SCORE_DISCLAIMER)
    st.subheader("Resultados del archivo")
    display_report = _prediction_report_for_display(report)
    st.dataframe(
        display_report,
        width="stretch",
        hide_index=True,
        column_config={
            SCORE_DISPLAY_LABEL: st.column_config.NumberColumn(
                SCORE_DISPLAY_LABEL,
                format="%.4f",
            )
        },
    )

    st.subheader("Clasificación obtenida")
    counts = pd.DataFrame(
        {
            "Registros": [normal, suspicious],
        },
        index=["Normal", "Sospechoso (ataque)"],
    )
    st.bar_chart(counts, color="#2463a6")
    if not suspicious:
        st.info("El modelo no clasificó registros como sospechosos en este archivo.")


def _csv_download_bytes(frame: pd.DataFrame) -> bytes:
    safe_frame = frame.copy()

    def neutralize_formula(value):
        if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
            return "'" + value
        return value

    for column in safe_frame.select_dtypes(include=["object", "string"]).columns:
        safe_frame[column] = safe_frame[column].map(neutralize_formula)
    return safe_frame.to_csv(index=False).encode("utf-8-sig")


def _render_history(database_path: Path) -> None:
    st.header("Historial de análisis")
    try:
        runs = list_analysis_runs(database_path, limit=RUN_HISTORY_LIMIT)
        alerts = list_alerts(database_path, limit=ALERT_HISTORY_LIMIT)
    except PersistenceError as error:
        st.error(f"No se pudo consultar el historial SQLite: {error}")
        return

    st.info(
        f"Este historial consulta como máximo las {RUN_HISTORY_LIMIT} ejecuciones "
        f"más recientes y las {ALERT_HISTORY_LIMIT:,} alertas más recientes. "
        "Los filtros, la búsqueda y «Todas» se aplican solo a las alertas "
        "cargadas; si se alcanza el límite, puede haber registros anteriores "
        "que no estén incluidos."
    )

    review_confirmation = st.session_state.pop("review_confirmation_message", None)
    if review_confirmation:
        st.success(review_confirmation)

    if not runs:
        st.info("Todavía no hay ejecuciones guardadas en la base local.")
    else:
        run_frame = pd.DataFrame(runs)
        display_columns = [
            "started_at",
            "source",
            "model_id",
            "model_reference",
            "decision_rule",
            "decision_threshold",
            "status",
            "records_processed",
            "alerts_created",
            "run_id",
        ]
        for column in display_columns:
            if column not in run_frame:
                run_frame[column] = None
        st.dataframe(
            run_frame.loc[:, display_columns],
            width="stretch",
            hide_index=True,
            column_config={
                "started_at": "Fecha y hora (UTC)",
                "source": "Archivo de origen",
                "model_id": "Modelo",
                "model_reference": "Artefacto",
                "decision_rule": "Regla de decisión",
                "decision_threshold": st.column_config.NumberColumn(
                    "Umbral",
                    format="%.2f",
                ),
                "status": "Estado",
                "records_processed": "Registros",
                "alerts_created": "Alertas",
                "run_id": "Ejecución",
            },
        )

        failed_runs = [
            run for run in runs if run.get("status") == "failed"
        ]
        if failed_runs:
            st.subheader("Ejecuciones fallidas")
            for run in failed_runs:
                run_id = str(run.get("run_id") or "no disponible")
                with st.expander(f"Ejecución fallida · {run_id}"):
                    st.write(
                        _safe_run_error_description(run.get("error_message"))
                    )

        st.subheader("Actividad por ejecución")
        chart = run_frame.set_index("started_at")[["records_processed", "alerts_created"]]
        chart.columns = ["Registros analizados", "Alertas"]
        st.bar_chart(chart, color=["#64748b", "#d97706"])

        st.download_button(
            "Descargar historial de ejecuciones (CSV)",
            data=_csv_download_bytes(_safe_run_history_export(run_frame)),
            file_name="historial_ejecuciones.csv",
            mime="text/csv",
            key="download_run_history",
        )

    st.header("Gestión de alertas")
    st.caption(
        "La revisión manual: marcar una alerta como confirmada no modifica "
        "la predicción del modelo ni significa por sí solo que sea un ataque real."
    )
    st.caption(
        "La fecha indica cuándo se registró la alerta en SQLite, no necesariamente "
        "cuándo ocurrió el evento de red."
    )
    st.caption(
        "El score del modelo (clase 1) no es necesariamente una probabilidad "
        "calibrada y no confirma por sí solo un ataque."
    )
    if not alerts:
        st.info("El historial no contiene alertas predichas.")
        return
    alert_frame = pd.DataFrame(alerts)
    alert_frame["model_id"] = alert_frame["model_id"].astype("object")
    model_ids = sorted(
        str(value)
        for value in alert_frame["model_id"].dropna().unique().tolist()
    )
    model_filter_options = [
        ALL_FILTER_VALUE,
        *model_ids,
        *(
            [MISSING_MODEL_FILTER_VALUE]
            if alert_frame["model_id"].isna().any()
            else []
        ),
    ]
    run_ids = alert_frame["run_id"].astype(str).drop_duplicates().tolist()
    run_sources = {
        str(row["run_id"]): row.get("source")
        for _, row in alert_frame.iterrows()
    }

    with st.expander(
        "Filtros de alertas",
        icon=":material/filter_alt:",
        expanded=True,
    ):
        filter_columns = st.columns(3)
        selected_model_filter = filter_columns[0].selectbox(
            "Modelo",
            options=model_filter_options,
            format_func=lambda value: (
                "Todos los modelos"
                if value == ALL_FILTER_VALUE
                else (
                    "Modelo no disponible (histórico)"
                    if value == MISSING_MODEL_FILTER_VALUE
                    else _format_alert_model(value)
                )
            ),
            key="alert_model_filter",
        )
        selected_run_filter = filter_columns[1].selectbox(
            "Ejecución",
            options=[ALL_FILTER_VALUE, *run_ids],
            format_func=lambda value: (
                "Todas las ejecuciones"
                if value == ALL_FILTER_VALUE
                else f"{run_sources.get(value) or 'Origen no disponible'} — {value}"
            ),
            key="alert_run_filter",
        )
        selected_review_filter = filter_columns[2].selectbox(
            "Estado de revisión",
            options=[ALL_FILTER_VALUE, *sorted(REVIEW_STATES)],
            format_func=lambda value: (
                "Todos los estados"
                if value == ALL_FILTER_VALUE
                else _format_review_state(value)
            ),
            key="alert_review_filter",
        )
        record_query = st.text_input(
            "Buscar identificador del registro",
            key="alert_record_search",
            placeholder="Escriba parte o todo el identificador",
        )

    filtered_alerts = _filter_alerts(
        alert_frame,
        model_id=selected_model_filter,
        run_id=selected_run_filter,
        review_state=selected_review_filter,
        record_id_query=record_query,
    )
    st.caption(
        f"Mostrando {len(filtered_alerts):,} de {len(alert_frame):,} alertas "
        "guardadas. Los filtros no modifican SQLite."
    )
    if filtered_alerts.empty:
        st.info("No hay alertas que coincidan con los filtros seleccionados.")
        return

    display_frame = filtered_alerts.copy()
    display_frame["modelo"] = display_frame["model_id"].map(_format_alert_model)
    display_frame["regla_clasificacion"] = display_frame.apply(
        _format_model_rule,
        axis=1,
    )
    display_frame["clase_predicha"] = display_frame["predicted_class"].map(
        {0: "Normal (clase 0)", 1: "Sospechoso (clase 1)"}
    )
    display_frame["estado_revision"] = display_frame["review_state"].map(
        _format_review_state
    )
    display_frame = display_frame.rename(
        columns={
            "alert_id": "ID de alerta",
            "record_id": "Identificador del registro",
            "detected_at": "Alerta registrada (UTC)",
            "model_score": "Score del modelo (clase 1)",
            "source": "Archivo de origen",
            "run_id": "ID de ejecución",
            "decision_threshold": "Umbral",
        }
    )
    st.dataframe(
        display_frame.loc[
            :,
            [
                "ID de alerta",
                "Identificador del registro",
                "Alerta registrada (UTC)",
                "clase_predicha",
                "Score del modelo (clase 1)",
                "modelo",
                "regla_clasificacion",
                "Umbral",
                "Archivo de origen",
                "estado_revision",
                "ID de ejecución",
            ],
        ],
        width="stretch",
        hide_index=True,
        column_config={
            "ID de alerta": "Alerta",
            "Identificador del registro": "Registro",
            "Alerta registrada (UTC)": "Alerta registrada (UTC)",
            "clase_predicha": "Clase predicha",
            "Score del modelo (clase 1)": st.column_config.NumberColumn(
                "Score del modelo (clase 1)",
                format="%.4f",
            ),
            "modelo": "Modelo utilizado",
            "regla_clasificacion": "Regla de clasificación",
            "Umbral": st.column_config.NumberColumn("Umbral", format="%.2f"),
            "Archivo de origen": "Archivo de origen",
            "estado_revision": "Estado de revisión",
            "ID de ejecución": "Ejecución",
        },
    )

    filtered_ids = filtered_alerts["alert_id"].astype(int).tolist()
    if st.session_state.get("review_alert_id") not in filtered_ids:
        st.session_state["review_alert_id"] = filtered_ids[0]
        selected_review_state = filtered_alerts.iloc[0]["review_state"]
        st.session_state["review_alert_state"] = REVIEW_LABELS[
            selected_review_state
        ]
    elif "review_alert_state" not in st.session_state:
        selected_review_state = filtered_alerts.loc[
            filtered_alerts["alert_id"] == st.session_state["review_alert_id"],
            "review_state",
        ].iloc[0]
        st.session_state["review_alert_state"] = REVIEW_LABELS[
            selected_review_state
        ]
    alert_review_states = {
        int(row["alert_id"]): str(row["review_state"])
        for _, row in filtered_alerts.iterrows()
    }
    st.caption(
        "Para consultar los detalles, seleccione una alerta en el menú siguiente. "
        "Hacer clic en una fila de la tabla no selecciona la alerta"
    )
    selected_id = st.selectbox(
        "Alerta para revisar",
        options=filtered_ids,
        format_func=lambda alert_id: (
            f"Alerta {alert_id} — "
            f"{filtered_alerts.loc[filtered_alerts['alert_id'] == alert_id, 'record_id'].iloc[0]}"
        ),
        key="review_alert_id",
        on_change=_reset_review_state_for_selected_alert,
        args=(alert_review_states,),
    )
    selected_alert = filtered_alerts.loc[
        filtered_alerts["alert_id"] == selected_id
    ].iloc[0]

    with st.container(border=True):
        st.subheader("🚨 Detalle de la alerta")
        detail_left, detail_right = st.columns(2)
        detail_left.markdown("**¿Qué significa esta alerta?**")
        detail_left.write(
            "El modelo clasificó este registro como sospechoso según la regla "
            "indicada. Es una señal para revisión, no una confirmación automática "
            "de un ataque."
        )
        detail_left.write(
            "El score es una salida del modelo y no necesariamente una probabilidad "
            "calibrada. La aplicación no tiene explicabilidad implementada y no "
            "puede identificar aquí la causa exacta de la predicción."
        )
        detail_right.markdown("**Identificación y revisión**")
        detail_right.write(f"Alerta: `{selected_alert['alert_id']}`")
        detail_right.write(f"Registro: `{selected_alert['record_id']}`")
        detail_right.write(
            f"Clase predicha: "
            f"{'Sospechoso (clase 1)' if selected_alert['predicted_class'] == 1 else 'Normal (clase 0)'}"
        )
        detail_right.write(
            f"Estado: {_format_review_state(selected_alert['review_state'])}"
        )
        detail_right.write(
            "Alerta registrada (UTC): "
            f"`{selected_alert['detected_at']}`"
        )
        detail_right.caption(
            "La fecha es la hora de registro en SQLite; no necesariamente "
            "el momento del evento de red."
        )

        st.markdown("**Modelo y origen**")
        st.write(f"Modelo: {_format_alert_model(selected_alert['model_id'])}")
        st.write(f"Regla: {_format_model_rule(selected_alert)}")
        if selected_alert["decision_threshold"] is not None:
            st.write(f"Umbral: {float(selected_alert['decision_threshold']):.2f}")
        score = selected_alert["model_score"]
        st.write(
            "Score del modelo (clase 1): "
            + ("No disponible" if score is None else f"{float(score):.4f}")
        )
        st.write(
            f"Archivo de origen: {selected_alert['source'] or 'No disponible'}"
        )
        st.write(f"Ejecución: `{selected_alert['run_id']}`")
        if selected_alert["model_reference"]:
            st.caption(f"Artefacto: `{selected_alert['model_reference']}`")
        if selected_alert["model_sha256"]:
            st.caption(f"SHA-256 del modelo: `{selected_alert['model_sha256']}`")

    st.download_button(
        "Descargar alertas filtradas (CSV)",
        data=_csv_download_bytes(filtered_alerts),
        file_name="alertas.csv",
        mime="text/csv",
        key="download_alert_history",
    )

    state_descriptions = (
        "- **Pendiente de revisión:** todavía no hay una revisión manual.\n"
        "- **Confirmada (revisión manual):** una persona confirmó la revisión; "
        "esto no es evidencia técnica concluyente de un ataque.\n"
        "- **Falso positivo:** una persona revisora considera que la alerta no "
        "corresponde a una detección válida."
    )
    with st.expander("Qué significan los estados de revisión"):
        st.markdown(state_descriptions)

    selected_label = st.selectbox(
        "Nuevo estado de revisión",
        options=list(REVIEW_OPTIONS),
        key="review_alert_state",
    )
    if st.button("Guardar revisión", key="update_alert_review"):
        try:
            update_alert_review_state(
                database_path,
                int(selected_id),
                REVIEW_OPTIONS[selected_label],
            )
        except PersistenceError as error:
            st.error(f"No se pudo actualizar la alerta: {error}")
        else:
            st.session_state["review_confirmation_message"] = (
                f"Alerta {int(selected_id)} actualizada: {selected_label}."
            )
            st.rerun()


def render_dashboard(
    model_path: str | Path = DEFAULT_MODEL_PATH,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
    model_path_override: bool | None = None,
) -> None:
    """Renderiza el panel conectado al modelo serializado y SQLite local."""

    model_path = Path(model_path)
    database_path = Path(database_path)
    if model_path_override is None:
        model_path_override = (
            "SIPYMES_MODEL_PATH" in os.environ
            or model_path.resolve() != DEFAULT_MODEL_PATH.resolve()
        )
    st.set_page_config(
        page_title="Seguridad Inteligente PYMES",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("Seguridad Inteligente PYMES")
    st.caption("Monitoreo autorizado por reglas y análisis independiente de archivos CSV.")
    from seguridad_pymes.monitor_ui import render_network_monitor
    render_network_monitor()
    st.divider()
    st.header("Análisis CSV con aprendizaje automático")
    st.warning(
        "**Esta sección: análisis por archivo, no monitoreo en tiempo real.** "
        "Procesa un CSV con el modelo original UNSW-NB15. El monitoreo de la "
        "interfaz seleccionada se controla en la sección superior y utiliza reglas, no este modelo.",
        icon="⚠️",
    )

    with st.sidebar:
        st.header("Estado del sistema")
        model = None
        configuration = None
        expected_features: tuple[str, ...] = ()
        production_model = None
        experimental_model = None
        production_error = None
        experimental_error = None
        selected_builtin = not model_path_override or (
            model_path.resolve() in {
                DEFAULT_MODEL_PATH.resolve(),
                model_configuration(THRESHOLD_STUDY_MODEL_ID).model_path.resolve(),
            }
        )

        if selected_builtin:
            try:
                production_path = DEFAULT_MODEL_PATH
                production_model = _load_model(
                    str(production_path),
                    production_path.stat().st_mtime_ns,
                )
                production_schema, _ = _model_input_schema(production_model)
                if len(production_schema) != 42:
                    raise ValueError(
                        "El modelo definitivo debe declarar exactamente 42 "
                        "características."
                    )
            except (
                OSError,
                ValueError,
                TypeError,
                EOFError,
                ImportError,
                AttributeError,
                KeyError,
                RuntimeError,
            ) as error:
                production_error = error

            try:
                experimental_path = model_configuration(
                    THRESHOLD_STUDY_MODEL_ID
                ).model_path
                experimental_model = _load_model(
                    str(experimental_path),
                    experimental_path.stat().st_mtime_ns,
                )
                if production_model is None:
                    raise ValueError(
                        "No se pudo validar contra el esquema del modelo definitivo."
                    )
                _validate_builtin_model_pair(production_model, experimental_model)
            except (
                OSError,
                ValueError,
                TypeError,
                EOFError,
                ImportError,
                AttributeError,
                KeyError,
                RuntimeError,
            ) as error:
                experimental_error = error

            if model_path_override:
                try:
                    configuration = infer_model_configuration(model_path)
                    if configuration.model_id == PRODUCTION_MODEL_ID:
                        if production_model is None:
                            raise ValueError(str(production_error))
                        model = production_model
                    else:
                        if experimental_model is None or experimental_error is not None:
                            raise ValueError(
                                f"No se puede usar el override experimental: "
                                f"{experimental_error}"
                            )
                        model = experimental_model
                except (
                    OSError,
                    ValueError,
                    TypeError,
                    EOFError,
                    ImportError,
                    AttributeError,
                    KeyError,
                    RuntimeError,
                ) as error:
                    st.error(f"No se pudo cargar el override del modelo: {error}")
                else:
                    st.info(
                        "SIPYMES_MODEL_PATH está definido: el selector está "
                        "deshabilitado y se usa el artefacto indicado."
                    )
            elif production_model is None:
                st.error(f"No se pudo cargar el modelo definitivo: {production_error}")
            else:
                available = {
                    PRODUCTION_MODEL_ID: PRODUCTION_MODEL_LABEL,
                }
                if experimental_model is not None and experimental_error is None:
                    available[THRESHOLD_STUDY_MODEL_ID] = (
                        THRESHOLD_STUDY_MODEL_LABEL
                    )
                else:
                    st.warning(
                        "El modelo experimental no está disponible; se mantiene "
                        f"el definitivo. Detalle: {experimental_error}"
                    )
                selected_label = st.selectbox(
                    "Modelo de clasificación",
                    options=list(available.values()),
                    index=0,
                    key="model_selection",
                )
                selected_id = next(
                    key for key, label in available.items() if label == selected_label
                )
                configuration = model_configuration(selected_id)
                model = (
                    production_model
                    if selected_id == PRODUCTION_MODEL_ID
                    else experimental_model
                )

            if model is not None:
                expected_features = _model_features(model)
                st.success("Modelo cargado y listo.")
                st.caption(f"Modelo seleccionado: {configuration.label}")
                st.caption(f"Artefacto: `{configuration.model_path}`")
                st.caption(f"Características requeridas: {len(expected_features)}")
                st.caption(f"Regla: `{configuration.decision_rule}`")
                st.caption(
                    "Umbral: clasificación predeterminada"
                    if configuration.decision_threshold is None
                    else f"Umbral: {configuration.decision_threshold:.2f}"
                )
        else:
            configuration = infer_model_configuration(model_path)
            try:
                model = _load_model(
                    str(configuration.model_path),
                    configuration.model_path.stat().st_mtime_ns,
                )
                expected_features = _model_features(model)
            except (
                OSError,
                ValueError,
                TypeError,
                EOFError,
                ImportError,
                AttributeError,
                KeyError,
                RuntimeError,
            ) as error:
                st.error(f"No se pudo cargar el override del modelo: {error}")
            else:
                st.info(
                    "SIPYMES_MODEL_PATH está definido: el selector está "
                    "deshabilitado y se usa el artefacto indicado."
                )
                st.success("Modelo cargado y listo.")
                st.caption(f"Modelo seleccionado: {configuration.label}")
                st.caption(f"Regla: `{configuration.decision_rule}`")
                st.caption(f"Características requeridas: {len(expected_features)}")
        st.caption(f"Base SQLite: `{database_path}`")
        st.caption("Clasificación: normal (0) / sospechoso (1)")

    try:
        initialize_database(database_path)
    except PersistenceError as error:
        st.error(f"No se pudo inicializar la base SQLite: {error}")
        return

    st.header("Analizar un archivo")
    st.write(
        "Seleccione un CSV que contenga las características requeridas por el "
        "modelo. Puede incluir `id` para identificar filas; `label` y `attack_cat` "
        "se ignoran y nunca se utilizan para predecir."
    )
    uploaded_file = st.file_uploader(
        "Archivo CSV de registros",
        type=["csv"],
        accept_multiple_files=False,
        max_upload_size=MAX_UPLOAD_BYTES // (1024 * 1024),
        help="CSV UTF-8 de hasta 100 MB. El archivo no se envía a servicios externos.",
    )

    if uploaded_file is not None:
        try:
            uploaded_frame, headers = _read_uploaded_csv(uploaded_file)
            if model is None:
                st.info("Cargue un modelo válido antes de ejecutar el análisis.")
            else:
                expected_features = _model_features(model)
                records, record_ids, metadata_columns = _prepare_uploaded_records(
                    uploaded_frame,
                    headers,
                    expected_features,
                    uploaded_file.name,
                )
                st.success(
                    f"Archivo validado: {len(records):,} registros y "
                    f"{len(expected_features)} características compatibles."
                )
                if metadata_columns:
                    st.caption(
                        "Columnas de metadatos excluidas de la predicción: "
                        + ", ".join(f"`{column}`" for column in metadata_columns)
                        + "."
                    )
                if not any(column.casefold() == "id" for column in headers):
                    st.caption(
                        "El archivo no incluye `id`; se usarán referencias a filas "
                        "basadas en el nombre del archivo y su posición."
                    )

                if st.button(
                    "Ejecutar análisis del archivo",
                    type="primary",
                    disabled=model is None,
                ):
                    try:
                        with st.spinner("Ejecutando el modelo y guardando resultados…"):
                            result = run_model_analysis(
                                records,
                                record_ids,
                                source=uploaded_file.name,
                                model_path=configuration.model_path,
                                database_path=database_path,
                                model_id=configuration.model_id,
                            )
                    except (
                        ValueError,
                        OSError,
                        PersistenceError,
                        RuntimeError,
                        TypeError,
                        EOFError,
                        ImportError,
                        AttributeError,
                        KeyError,
                    ) as error:
                        st.error(f"No se pudo completar el análisis: {error}")
                    else:
                        report = _prediction_report(
                            result,
                            record_ids,
                            uploaded_file.name,
                        )
                        st.session_state["latest_report"] = report
                        st.session_state["latest_result"] = result
                        st.session_state["latest_run"] = {
                            "run_id": result.run_id,
                            "source": uploaded_file.name,
                            "records_processed": result.records_processed,
                            "alerts_created": result.alerts_created,
                            "model_id": result.model_id,
                            "model_reference": result.model_reference,
                            "decision_rule": result.decision_rule,
                            "decision_threshold": result.decision_threshold,
                            "model_sha256": result.model_sha256,
                        }
                        st.session_state["latest_database_path"] = str(database_path)
                        st.success("Análisis completado y registrado en la base local.")
        except (ValueError, OSError) as error:
            st.error(f"No se pudo validar el archivo: {error}")

    latest_report = st.session_state.get("latest_report")
    result = st.session_state.get("latest_result")
    latest_run = st.session_state.get("latest_run")
    if latest_report is not None and latest_run is not None:
        st.divider()
        st.header("Último análisis")
        st.caption(f"Archivo procesado: `{latest_run['source']}`")
        suspicious_count = int(
            (latest_report["clasificacion_predicha"] == "Sospechoso (ataque)").sum()
        )
        if not isinstance(result, InferenceRunResult):
            st.error("No se pudo recuperar el resultado de la última ejecución.")
            result = None
        if result is None:
            _render_history(database_path)
            return
        _render_summary(latest_report, result)
        st.download_button(
            "Descargar resultados de este análisis (CSV)",
            data=_csv_download_bytes(
                _prediction_report_for_display(latest_report)
            ),
            file_name="resultado_analisis.csv",
            mime="text/csv",
            key="download_current_csv",
        )
        try:
            latest_alerts = list_alerts(
                database_path,
                run_id=latest_run["run_id"],
                limit=10000,
            )
        except PersistenceError as error:
            st.error(f"No se pudieron recuperar las alertas del análisis: {error}")
            latest_alerts = []
        alerts_truncated = len(latest_alerts) < latest_run["alerts_created"]
        if alerts_truncated:
            st.caption(
                f"El reporte JSON incluye {len(latest_alerts):,} de "
                f"{latest_run['alerts_created']:,} alertas. La lista de alertas "
                f"está limitada a {ALERT_HISTORY_LIMIT:,}; los resultados por "
                "registro conservan todas las predicciones del análisis."
            )
        report_payload = {
            "run": latest_run,
            "normal_predictions": latest_run["records_processed"] - suspicious_count,
            "suspicious_predictions": suspicious_count,
            "alerts": latest_alerts,
            "alerts_total": latest_run["alerts_created"],
            "alerts_returned": len(latest_alerts),
            "alerts_limit": ALERT_HISTORY_LIMIT,
            "alerts_truncated": alerts_truncated,
            "resource_measurement": (
                None
                if result.resource_measurement is None
                else result.resource_measurement.__dict__
            ),
            "records": [
                {
                    key: None if pd.isna(value) else value
                    for key, value in record.items()
                }
                for record in _prediction_report_for_display(
                    latest_report
                ).to_dict(orient="records")
            ],
        }
        st.download_button(
            "Descargar reporte de este análisis (JSON)",
            data=json.dumps(report_payload, ensure_ascii=False, indent=2, default=str),
            file_name="resultado_analisis.json",
            mime="application/json",
            key="download_current_json",
        )

    st.divider()
    _render_history(database_path)
