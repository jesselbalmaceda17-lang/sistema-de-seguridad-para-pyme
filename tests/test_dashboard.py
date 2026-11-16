import unittest
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pandas as pd
import joblib
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from streamlit.testing.v1 import AppTest

from seguridad_pymes.database import (
    complete_analysis_run,
    create_analysis_run,
    fail_analysis_run,
    initialize_database,
    list_alerts,
    list_analysis_runs,
    update_alert_review_state,
)
from seguridad_pymes.dashboard import (
    GENERIC_RUN_ERROR_DESCRIPTION,
    SCORE_DISCLAIMER,
    SCORE_DISPLAY_LABEL,
    SCORE_REPORT_COLUMN,
    _prediction_report,
    _prediction_report_for_display,
    _render_summary,
    _safe_run_error_description,
    _safe_run_history_export,
)
from seguridad_pymes.dashboard import (
    ALL_FILTER_VALUE,
    MISSING_MODEL_FILTER_VALUE,
    _csv_download_bytes,
    _filter_alerts,
    _format_alert_model,
    _format_model_rule,
    _format_review_state,
    _prepare_uploaded_records,
    _read_uploaded_csv,
    _validate_builtin_model_pair,
)
from seguridad_pymes.inference import InferenceRunResult


class UploadedFileStub:
    def __init__(self, data):
        self.data = data

    def getvalue(self):
        return self.data


class DashboardInputTests(unittest.TestCase):
    """Verifica validación de archivos y preparación sin ejecutar UI real."""

    def test_reads_compatible_csv_and_uses_source_ids(self):
        content = (
            "id,bytes,protocol,label,attack_cat\n"
            "flow-1,120,TCP,0,Normal\n"
            "flow-2,900,UDP,1,DoS\n"
        ).encode("utf-8")
        frame, headers = _read_uploaded_csv(UploadedFileStub(content))

        records, record_ids, metadata = _prepare_uploaded_records(
            frame,
            headers,
            ("bytes", "protocol"),
            "flows.csv",
        )

        self.assertEqual(record_ids, ["flow-1", "flow-2"])
        self.assertEqual(records.columns.tolist(), ["bytes", "protocol"])
        self.assertEqual(metadata, ["id", "label", "attack_cat"])
        self.assertEqual(records.iloc[0]["bytes"], "120")

    def test_generates_row_references_when_no_id_column_exists(self):
        content = "bytes,protocol\n12,TCP\n".encode("utf-8")
        frame, headers = _read_uploaded_csv(UploadedFileStub(content))

        _, record_ids, _ = _prepare_uploaded_records(
            frame,
            headers,
            ("bytes", "protocol"),
            "capture.csv",
        )

        self.assertEqual(record_ids, ["capture.csv:fila-2"])

    def test_rejects_bad_encoding_empty_csv_oversize_and_duplicate_headers(self):
        for payload, expected in (
            (b"\xff\xfe", "UTF-8"),
            (b"", "vacío"),
            (b"a,a\n1,2\n", "duplicados"),
            (b"a\n1\n", "100 MB"),
        ):
            with self.subTest(expected=expected):
                if expected == "100 MB":
                    from seguridad_pymes import dashboard

                    original_limit = dashboard.MAX_UPLOAD_BYTES
                    dashboard.MAX_UPLOAD_BYTES = 10
                    try:
                        with self.assertRaisesRegex(ValueError, expected):
                            _read_uploaded_csv(UploadedFileStub(b"x" * 11))
                    finally:
                        dashboard.MAX_UPLOAD_BYTES = original_limit
                else:
                    with self.assertRaisesRegex(ValueError, expected):
                        _read_uploaded_csv(UploadedFileStub(payload))

    def test_rejects_schema_mismatch_missing_values_and_duplicate_ids(self):
        content = "id,bytes,protocol\none,12,TCP\ntwo,,UDP\n".encode("utf-8")
        frame, headers = _read_uploaded_csv(UploadedFileStub(content))

        with self.assertRaisesRegex(ValueError, "valores faltantes"):
            _prepare_uploaded_records(frame, headers, ("bytes", "protocol"), "flows.csv")
        with self.assertRaisesRegex(ValueError, "faltan características"):
            _prepare_uploaded_records(frame.iloc[[0]], headers, ("bytes", "service"), "flows.csv")

        duplicate_content = "id,bytes,protocol\na,1,TCP\na,2,UDP\n".encode("utf-8")
        duplicate_frame, duplicate_headers = _read_uploaded_csv(
            UploadedFileStub(duplicate_content)
        )
        with self.assertRaisesRegex(ValueError, "duplicados"):
            _prepare_uploaded_records(
                duplicate_frame,
                duplicate_headers,
                ("bytes", "protocol"),
                "flows.csv",
            )

    def test_csv_export_neutralizes_spreadsheet_formulas(self):
        exported = _csv_download_bytes(
            pd.DataFrame({"record_id": ["=HYPERLINK('x')", "normal"], "label": [1, 0]})
        ).decode("utf-8-sig")

        self.assertIn("'=HYPERLINK", exported)
        self.assertIn("normal", exported)

    def test_prediction_report_contains_actual_results_and_source(self):
        result = InferenceRunResult(
            run_id="real-run-id",
            records_processed=2,
            alerts_created=1,
            predictions=(0, 1),
            attack_scores=(0.12, 0.93),
            database_path=Path("unused.sqlite3"),
        )

        report = _prediction_report(result, ["r-1", "r-2"], "flows.csv")
        display_report = _prediction_report_for_display(report)

        self.assertEqual(report["clasificacion_predicha"].tolist(), ["Normal", "Sospechoso (ataque)"])
        self.assertEqual(report[SCORE_REPORT_COLUMN].tolist(), [0.12, 0.93])
        self.assertIn(SCORE_REPORT_COLUMN, report.columns)
        self.assertNotIn(SCORE_DISPLAY_LABEL, report.columns)
        self.assertEqual(
            display_report[SCORE_DISPLAY_LABEL].tolist(),
            [0.12, 0.93],
        )
        self.assertNotIn(SCORE_REPORT_COLUMN, display_report.columns)
        exported = _csv_download_bytes(display_report).decode("utf-8-sig")
        self.assertIn(SCORE_DISPLAY_LABEL, exported.splitlines()[0])
        self.assertNotIn("probabilidad_ataque", exported.splitlines()[0])
        self.assertIn("no es necesariamente una probabilidad", SCORE_DISCLAIMER)
        self.assertIn("ni confirma un ataque", SCORE_DISCLAIMER)
        self.assertIn(SCORE_DISPLAY_LABEL, display_report.to_dict(orient="records")[0])
        self.assertEqual(report["archivo_origen"].unique().tolist(), ["flows.csv"])
        self.assertEqual(report["id_ejecucion"].unique().tolist(), ["real-run-id"])
        self.assertIn("modelo", report.columns)
        self.assertIn("regla_decision", report.columns)
        self.assertIn("umbral_decision", report.columns)

    def test_summary_displays_score_label_and_disclaimer(self):
        result = InferenceRunResult(
            run_id="summary-run",
            records_processed=1,
            alerts_created=0,
            predictions=(0,),
            attack_scores=(0.12,),
            database_path=Path("unused.sqlite3"),
        )
        report = _prediction_report(result, ["r-1"], "flows.csv")

        with patch("seguridad_pymes.dashboard.st") as streamlit:
            streamlit.columns.return_value = (Mock(), Mock(), Mock(), Mock())
            _render_summary(report, result)

        streamlit.caption.assert_any_call(SCORE_DISCLAIMER)
        displayed_report = streamlit.dataframe.call_args.args[0]
        self.assertIn(SCORE_DISPLAY_LABEL, displayed_report.columns)
        self.assertNotIn(SCORE_REPORT_COLUMN, displayed_report.columns)

    def test_failed_run_error_summary_is_safe_and_historical_nulls_are_supported(self):
        stored_error = (
            "RuntimeError: internal failure at "
            r"C:\Users\example\private\model.joblib api_key=secret-value"
        )
        safe_description = _safe_run_error_description(stored_error)

        self.assertIn("no pudo completarse", safe_description)
        self.assertNotIn("RuntimeError", safe_description)
        self.assertNotIn(r"C:\Users", safe_description)
        self.assertNotIn("secret-value", safe_description)
        self.assertEqual(
            _safe_run_error_description(None),
            GENERIC_RUN_ERROR_DESCRIPTION,
        )
        self.assertEqual(
            _safe_run_error_description("legacy error with no type"),
            GENERIC_RUN_ERROR_DESCRIPTION,
        )

        exported = _safe_run_history_export(
            pd.DataFrame(
                [
                    {"status": "failed", "error_message": stored_error},
                    {"status": "completed", "error_message": None},
                ]
            )
        )
        self.assertEqual(exported.loc[0, "error_message"], safe_description)
        self.assertTrue(pd.isna(exported.loc[1, "error_message"]))
        self.assertNotIn("secret-value", exported.to_csv(index=False))

    def test_history_discloses_query_limits_and_safely_shows_failed_run(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            database_path = root / "history.sqlite3"
            model_path = root / "missing.joblib"
            initialize_database(database_path)
            failed_run = create_analysis_run(
                database_path,
                source="upload.csv",
                model_reference="model.joblib",
            )
            fail_analysis_run(
                database_path,
                failed_run,
                "RuntimeError: internal detail secret-value",
            )
            stored_run = next(
                run
                for run in list_analysis_runs(database_path)
                if run["run_id"] == failed_run
            )
            self.assertEqual(
                stored_run["error_message"],
                "RuntimeError: internal detail secret-value",
            )
            create_analysis_run(
                database_path,
                source="legacy-upload.csv",
                model_reference="legacy-model.joblib",
            )

            old_model_path = os.environ.get("SIPYMES_MODEL_PATH")
            old_database_path = os.environ.get("SIPYMES_DATABASE_PATH")
            os.environ["SIPYMES_MODEL_PATH"] = str(model_path)
            os.environ["SIPYMES_DATABASE_PATH"] = str(database_path)
            try:
                app_path = Path(__file__).resolve().parents[1] / "app.py"
                app = AppTest.from_file(str(app_path)).run(timeout=30)
            finally:
                if old_model_path is None:
                    os.environ.pop("SIPYMES_MODEL_PATH", None)
                else:
                    os.environ["SIPYMES_MODEL_PATH"] = old_model_path
                if old_database_path is None:
                    os.environ.pop("SIPYMES_DATABASE_PATH", None)
                else:
                    os.environ["SIPYMES_DATABASE_PATH"] = old_database_path

            self.assertEqual(len(app.exception), 0)
            self.assertTrue(
                any(
                    "100 ejecuciones más recientes" in item.value
                    and "10,000 alertas más recientes" in item.value
                    and "«Todas»" in item.value
                    for item in app.info
                )
            )
            self.assertTrue(
                any(
                    "Ejecución fallida ·" in item.label
                    for item in app.expander
                )
            )
            rendered_text = "\n".join(
                item.value
                for elements in (app.markdown, app.caption, app.info)
                for item in elements
            )
            self.assertIn("no pudo completarse", rendered_text)
            self.assertNotIn("secret-value", rendered_text)
            self.assertNotIn("internal detail", rendered_text)

    def test_builtin_models_require_identical_42_feature_schemas(self):
        names = tuple(f"feature_{index}" for index in range(42))
        numeric = names[:39]

        def fake_model(feature_names, numeric_names):
            preprocessing = SimpleNamespace(
                feature_names_in_=feature_names,
                named_transformers_={
                    "numeric": SimpleNamespace(feature_names_in_=numeric_names)
                },
            )
            return SimpleNamespace(
                named_steps={
                    "preprocessing": preprocessing,
                    "classifier": SimpleNamespace(classes_=[0, 1]),
                },
                predict_proba=lambda _: None,
            )

        production = fake_model(names, numeric)
        experimental = fake_model(names, numeric)
        self.assertEqual(
            _validate_builtin_model_pair(production, experimental),
            names,
        )

        with self.assertRaisesRegex(ValueError, "42 características"):
            _validate_builtin_model_pair(
                production,
                fake_model(names[:-1], numeric[:-1]),
            )
        different_names = (*names[:-1], "different_feature")
        with self.assertRaisesRegex(ValueError, "no comparten"):
            _validate_builtin_model_pair(
                production,
                fake_model(different_names, numeric),
            )

    def test_alert_filters_support_all_model_run_review_and_record_search(self):
        alerts = pd.DataFrame(
            [
                {
                    "alert_id": 1,
                    "record_id": "Flow-ABC",
                    "run_id": "run-one",
                    "model_id": "production_random_forest",
                    "review_state": "pending",
                },
                {
                    "alert_id": 2,
                    "record_id": "flow-xyz",
                    "run_id": "run-two",
                    "model_id": "threshold_study_random_forest",
                    "review_state": "confirmed",
                },
                {
                    "alert_id": 3,
                    "record_id": "legacy-flow",
                    "run_id": "run-legacy",
                    "model_id": None,
                    "review_state": "false_positive",
                },
            ]
        )

        all_alerts = _filter_alerts(
            alerts,
            model_id=ALL_FILTER_VALUE,
            run_id=ALL_FILTER_VALUE,
            review_state=ALL_FILTER_VALUE,
            record_id_query="",
        )
        self.assertEqual(len(all_alerts), 3)
        filtered = _filter_alerts(
            alerts,
            model_id="threshold_study_random_forest",
            run_id="run-two",
            review_state="confirmed",
            record_id_query="FLOW-X",
        )
        self.assertEqual(filtered["alert_id"].tolist(), [2])
        legacy = _filter_alerts(
            alerts,
            model_id=MISSING_MODEL_FILTER_VALUE,
            run_id=ALL_FILTER_VALUE,
            review_state=ALL_FILTER_VALUE,
            record_id_query="legacy",
        )
        self.assertEqual(legacy["alert_id"].tolist(), [3])

    def test_alert_presentation_uses_plain_language_and_no_fake_threshold(self):
        self.assertEqual(
            _format_model_rule(
                {"decision_rule": "predict", "decision_threshold": None}
            ),
            "Clasificación predeterminada",
        )
        self.assertEqual(
            _format_model_rule(
                {
                    "decision_rule": "predict_proba_gte",
                    "decision_threshold": 0.65,
                }
            ),
            "Score clase 1 ≥ 0.65",
        )
        self.assertEqual(
            _format_model_rule(
                {
                    "decision_rule": "predict_proba_gte",
                    "decision_threshold": None,
                }
            ),
            "Score clase 1 ≥ umbral no disponible",
        )
        self.assertEqual(
            _format_alert_model(None),
            "Modelo no disponible (ejecución histórica)",
        )
        self.assertEqual(_format_review_state("confirmed"), "Confirmada (revisión manual)")

    def test_streamlit_app_renders_without_model_or_real_data(self):
        old_model_path = os.environ.get("SIPYMES_MODEL_PATH")
        old_database_path = os.environ.get("SIPYMES_DATABASE_PATH")
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ["SIPYMES_MODEL_PATH"] = str(Path(temp_dir) / "missing.joblib")
            os.environ["SIPYMES_DATABASE_PATH"] = str(Path(temp_dir) / "history.sqlite3")
            try:
                app_path = Path(__file__).resolve().parents[1] / "app.py"
                app = AppTest.from_file(str(app_path)).run(timeout=30)
            finally:
                if old_model_path is None:
                    os.environ.pop("SIPYMES_MODEL_PATH", None)
                else:
                    os.environ["SIPYMES_MODEL_PATH"] = old_model_path
                if old_database_path is None:
                    os.environ.pop("SIPYMES_DATABASE_PATH", None)
                else:
                    os.environ["SIPYMES_DATABASE_PATH"] = old_database_path

        self.assertEqual(len(app.exception), 0)
        self.assertEqual(app.title[0].value, "Seguridad Inteligente PYMES")
        self.assertTrue(any("no monitoreo en tiempo real" in item.value for item in app.warning))

    def test_streamlit_app_reports_loaded_model(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            model_path = root / "fixture.joblib"
            database_path = root / "history.sqlite3"
            samples = pd.DataFrame({"flow_value": [0.0, 1.0, 9.0, 10.0]})
            pipeline = Pipeline(
                [
                    (
                        "preprocessing",
                        ColumnTransformer(
                            [("numeric", StandardScaler(), ["flow_value"])]
                        ),
                    ),
                    (
                        "classifier",
                        RandomForestClassifier(n_estimators=2, random_state=5),
                    ),
                ]
            )
            pipeline.fit(samples, [0, 0, 1, 1])
            joblib.dump(pipeline, model_path)

            old_model_path = os.environ.get("SIPYMES_MODEL_PATH")
            old_database_path = os.environ.get("SIPYMES_DATABASE_PATH")
            os.environ["SIPYMES_MODEL_PATH"] = str(model_path)
            os.environ["SIPYMES_DATABASE_PATH"] = str(database_path)
            try:
                app_path = Path(__file__).resolve().parents[1] / "app.py"
                app = AppTest.from_file(str(app_path)).run(timeout=30)
            finally:
                if old_model_path is None:
                    os.environ.pop("SIPYMES_MODEL_PATH", None)
                else:
                    os.environ["SIPYMES_MODEL_PATH"] = old_model_path
                if old_database_path is None:
                    os.environ.pop("SIPYMES_DATABASE_PATH", None)
                else:
                    os.environ["SIPYMES_DATABASE_PATH"] = old_database_path

        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any("Modelo cargado y listo." in item.value for item in app.success))
        self.assertTrue(
            any("Override explícito" in item.value for item in app.caption)
        )
        self.assertFalse(
            any(widget.key == "model_selection" for widget in app.selectbox)
        )

    def test_streamlit_selector_defaults_to_production_and_offers_experimental(self):
        old_model_path = os.environ.pop("SIPYMES_MODEL_PATH", None)
        old_database_path = os.environ.get("SIPYMES_DATABASE_PATH")
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ["SIPYMES_DATABASE_PATH"] = str(
                Path(temp_dir) / "selector-history.sqlite3"
            )
            try:
                app_path = Path(__file__).resolve().parents[1] / "app.py"
                app = AppTest.from_file(str(app_path)).run(timeout=60)
                selector = app.selectbox(key="model_selection")
                self.assertEqual(
                    selector.value,
                    "Definitivo — clasificación predeterminada",
                )
                self.assertIn("Experimental — umbral 0.65", selector.options)
                app.selectbox(key="model_selection").select(
                    "Experimental — umbral 0.65"
                ).run(timeout=60)
                experimental_path = (
                    Path(__file__).resolve().parents[1]
                    / "data"
                    / "processed"
                    / "threshold_study"
                    / "threshold_study_random_forest.joblib"
                )
                os.environ["SIPYMES_MODEL_PATH"] = str(experimental_path)
                override_app = AppTest.from_file(str(app_path)).run(timeout=60)
            finally:
                if old_model_path is not None:
                    os.environ["SIPYMES_MODEL_PATH"] = old_model_path
                if old_database_path is None:
                    os.environ.pop("SIPYMES_DATABASE_PATH", None)
                else:
                    os.environ["SIPYMES_DATABASE_PATH"] = old_database_path

        self.assertEqual(len(app.exception), 0)
        self.assertTrue(
            any("predict_proba_gte" in item.value for item in app.caption)
        )
        self.assertTrue(any("0.65" in item.value for item in app.caption))
        self.assertEqual(len(override_app.exception), 0)
        self.assertFalse(
            any(widget.key == "model_selection" for widget in override_app.selectbox)
        )
        self.assertTrue(
            any("SIPYMES_MODEL_PATH está definido" in item.value for item in override_app.info)
        )
        self.assertTrue(
            any("0.65" in item.value for item in override_app.caption)
        )

    def test_review_update_confirms_persists_refreshes_and_keeps_selected_alert(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            model_path = root / "missing.joblib"
            database_path = root / "history.sqlite3"
            initialize_database(database_path)
            run_id = create_analysis_run(
                database_path,
                source="fixture.csv",
                model_reference="fixture-model.joblib",
            )
            record_ids = [f"record-{index}" for index in range(1, 7)]
            record_ids.append("51025")
            complete_analysis_run(
                database_path,
                run_id,
                record_ids=record_ids,
                predictions=[1] * len(record_ids),
                scores=[0.9] * len(record_ids),
            )

            old_model_path = os.environ.get("SIPYMES_MODEL_PATH")
            old_database_path = os.environ.get("SIPYMES_DATABASE_PATH")
            os.environ["SIPYMES_MODEL_PATH"] = str(model_path)
            os.environ["SIPYMES_DATABASE_PATH"] = str(database_path)
            try:
                app_path = Path(__file__).resolve().parents[1] / "app.py"
                app = AppTest.from_file(str(app_path)).run(timeout=30)
                app.selectbox(key="review_alert_id").select(7).run()
                app.selectbox(key="review_alert_state").select(
                    "Confirmada (revisión manual)"
                ).run()
                app.button(key="update_alert_review").click().run()
                reloaded_app = AppTest.from_file(str(app_path)).run(timeout=30)
            finally:
                if old_model_path is None:
                    os.environ.pop("SIPYMES_MODEL_PATH", None)
                else:
                    os.environ["SIPYMES_MODEL_PATH"] = old_model_path
                if old_database_path is None:
                    os.environ.pop("SIPYMES_DATABASE_PATH", None)
                else:
                    os.environ["SIPYMES_DATABASE_PATH"] = old_database_path

            self.assertEqual(len(app.exception), 0)
            self.assertEqual(len(reloaded_app.exception), 0)
            self.assertTrue(
                any(item.value == "Gestión de alertas" for item in app.header)
            )
            self.assertTrue(
                any("revisión manual" in item.value for item in app.caption)
            )
            self.assertTrue(
                any(
                    "Alerta 7 actualizada: Confirmada (revisión manual)." in item.value
                    for item in app.success
                )
            )
            self.assertEqual(app.selectbox(key="review_alert_id").value, 7)
            self.assertNotIn("review_confirmation_message", app.session_state)
            alert = next(
                row for row in list_alerts(database_path) if row["alert_id"] == 7
            )
            self.assertEqual(alert["record_id"], "51025")
            self.assertEqual(alert["review_state"], "confirmed")
            self.assertEqual(
                {
                    row["alert_id"]: row["review_state"]
                    for row in list_alerts(database_path)
                },
                {
                    alert_id: (
                        "confirmed" if alert_id == 7 else "pending"
                    )
                    for alert_id in range(1, 8)
                },
            )
            alert_table = app.dataframe[1].value
            updated_row = alert_table.loc[
                alert_table["ID de alerta"] == 7
            ].iloc[0]
            self.assertEqual(updated_row["estado_revision"], "Confirmada (revisión manual)")
            self.assertEqual(updated_row["clase_predicha"], "Sospechoso (clase 1)")
            self.assertIn("Score del modelo (clase 1)", alert_table.columns)
            self.assertIn("Alerta registrada (UTC)", alert_table.columns)
            self.assertIn("modelo", alert_table.columns)
            self.assertIn("regla_clasificacion", alert_table.columns)
            self.assertIn("Archivo de origen", alert_table.columns)
            self.assertTrue(
                any(
                    "probabilidad calibrada" in item.value
                    for item in app.caption
                )
            )
            self.assertTrue(
                any("evento de red" in item.value for item in app.caption)
            )
            self.assertTrue(
                any(
                    item.value
                    == (
                        "Para consultar los detalles, seleccione una alerta en el "
                        "menú siguiente. Hacer clic en una fila de la tabla no "
                        "selecciona la alerta"
                    )
                    for item in app.caption
                )
            )
            detail_markdown = [item.value for item in app.markdown]
            self.assertTrue(
                any("¿Qué significa esta alerta?" in value for value in detail_markdown)
            )
            self.assertIn("Alerta: `7`", detail_markdown)
            self.assertIn("Registro: `51025`", detail_markdown)
            self.assertTrue(
                any("Detalle de la alerta" in item.value for item in app.subheader)
            )
            self.assertTrue(
                any(
                    "no puede identificar aquí la causa exacta" in value
                    for value in detail_markdown
                )
            )
            reloaded_alert_table = reloaded_app.dataframe[1].value
            reloaded_row = reloaded_alert_table.loc[
                reloaded_alert_table["ID de alerta"] == 7
            ].iloc[0]
            self.assertEqual(
                reloaded_row["estado_revision"],
                "Confirmada (revisión manual)",
            )

    def test_review_state_selector_tracks_each_alert_without_automatic_writes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            model_path = root / "missing.joblib"
            database_path = root / "history.sqlite3"
            initialize_database(database_path)
            run_id = create_analysis_run(
                database_path,
                source="two-alerts.csv",
                model_reference="fixture-model.joblib",
            )
            complete_analysis_run(
                database_path,
                run_id,
                record_ids=["confirmed-record", "pending-record"],
                predictions=[1, 1],
                scores=[0.8, 0.7],
            )
            alerts = list_alerts(database_path)
            alert_ids = {row["record_id"]: row["alert_id"] for row in alerts}
            update_alert_review_state(
                database_path,
                alert_ids["confirmed-record"],
                "confirmed",
            )

            old_model_path = os.environ.get("SIPYMES_MODEL_PATH")
            old_database_path = os.environ.get("SIPYMES_DATABASE_PATH")
            os.environ["SIPYMES_MODEL_PATH"] = str(model_path)
            os.environ["SIPYMES_DATABASE_PATH"] = str(database_path)
            try:
                app_path = Path(__file__).resolve().parents[1] / "app.py"
                app = AppTest.from_file(str(app_path)).run(timeout=30)
                app.selectbox(key="review_alert_id").select(
                    alert_ids["confirmed-record"]
                ).run()
                state_selector = app.selectbox(key="review_alert_state")
                self.assertEqual(
                    state_selector.value,
                    "Confirmada (revisión manual)",
                )

                state_selector.select("Falso positivo").run()
                self.assertEqual(
                    {
                        row["record_id"]: row["review_state"]
                        for row in list_alerts(database_path)
                    },
                    {
                        "confirmed-record": "confirmed",
                        "pending-record": "pending",
                    },
                )

                app.selectbox(key="review_alert_id").select(
                    alert_ids["pending-record"]
                ).run()
                self.assertEqual(
                    app.selectbox(key="review_alert_state").value,
                    "Pendiente de revisión",
                )
                self.assertEqual(
                    {
                        row["record_id"]: row["review_state"]
                        for row in list_alerts(database_path)
                    },
                    {
                        "confirmed-record": "confirmed",
                        "pending-record": "pending",
                    },
                )
            finally:
                if old_model_path is None:
                    os.environ.pop("SIPYMES_MODEL_PATH", None)
                else:
                    os.environ["SIPYMES_MODEL_PATH"] = old_model_path
                if old_database_path is None:
                    os.environ.pop("SIPYMES_DATABASE_PATH", None)
                else:
                    os.environ["SIPYMES_DATABASE_PATH"] = old_database_path


if __name__ == "__main__":
    unittest.main()
