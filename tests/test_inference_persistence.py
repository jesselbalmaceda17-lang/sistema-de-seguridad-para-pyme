import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

import joblib
import numpy as np
from seguridad_pymes.database import list_alerts, list_analysis_runs
from seguridad_pymes.inference import (
    PRODUCTION_MODEL_ID,
    THRESHOLD_STUDY_MODEL_ID,
    run_model_analysis,
)
from seguridad_pymes.resources import benchmark_inference, measure_operation


class InferencePersistenceTests(unittest.TestCase):
    """Usa fixtures aislados para verificar el wiring, no eficacia de red."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.model_path = self.root / "fixture-model.joblib"
        self.database_path = self.root / "fixture.sqlite3"

        training = pd.DataFrame(
            {
                "flow_value": [0.0, 0.1, 0.2, 0.3, 9.7, 9.8, 9.9, 10.0],
                "protocol_name": [
                    "TCP",
                    "TCP",
                    "TCP",
                    "TCP",
                    "UDP",
                    "UDP",
                    "UDP",
                    "UDP",
                ],
            }
        )
        labels = [0, 0, 0, 0, 1, 1, 1, 1]
        preprocessing = ColumnTransformer(
            [
                ("numeric", StandardScaler(), ["flow_value"]),
                (
                    "categorical",
                    OneHotEncoder(handle_unknown="ignore"),
                    ["protocol_name"],
                ),
            ]
        )
        model = Pipeline(
            [
                ("preprocessing", preprocessing),
                (
                    "classifier",
                    RandomForestClassifier(n_estimators=20, random_state=3),
                ),
            ]
        )
        model.fit(training, labels)
        joblib.dump(model, self.model_path)

    def test_run_persists_alerts_for_model_predictions_only(self):
        records = pd.DataFrame(
            {
                "flow_value": [0.05, 9.95],
                "protocol_name": ["TCP", "UDP"],
            }
        )

        result = run_model_analysis(
            records,
            ["normal-record", "attack-record"],
            source="unit-test-input.csv",
            model_path=self.model_path,
            database_path=self.database_path,
        )

        self.assertEqual(result.records_processed, 2)
        self.assertEqual(result.alerts_created, sum(result.predictions))
        self.assertEqual(len(result.attack_scores), 2)
        self.assertTrue(all(score is None or 0.0 <= score <= 1.0 for score in result.attack_scores))
        self.assertIsNotNone(result.resource_measurement)
        self.assertEqual(result.resource_measurement.sample_size, 2)
        self.assertGreaterEqual(result.resource_measurement.peak_rss_mib, 0)
        self.assertEqual(len(list_analysis_runs(self.database_path)), 1)
        self.assertEqual(
            {alert["record_id"] for alert in list_alerts(self.database_path)},
            {
                record_id
                for record_id, prediction in zip(
                    ("normal-record", "attack-record"), result.predictions
                )
                if prediction == 1
            },
        )
        self.assertEqual(list_analysis_runs(self.database_path)[0]["status"], "completed")

    def test_default_model_keeps_predict_and_persists_its_identity(self):
        records = pd.DataFrame(
            {"flow_value": [0.05, 9.95], "protocol_name": ["TCP", "UDP"]}
        )
        model = joblib.load(self.model_path)

        with (
            patch("seguridad_pymes.inference.DEFAULT_MODEL_PATH", self.model_path),
            patch("seguridad_pymes.inference.load_trained_model", return_value=model),
            patch.object(model, "predict", wraps=model.predict) as predict,
        ):
            result = run_model_analysis(
                records,
                ["normal-record", "attack-record"],
                source="default-model.csv",
                model_path=self.model_path,
                database_path=self.database_path,
            )

        predict.assert_called_once()
        self.assertEqual(result.model_id, PRODUCTION_MODEL_ID)
        self.assertEqual(result.decision_rule, "predict")
        self.assertIsNone(result.decision_threshold)
        run = list_analysis_runs(self.database_path)[0]
        self.assertEqual(run["model_id"], PRODUCTION_MODEL_ID)
        self.assertEqual(run["decision_rule"], "predict")
        self.assertIsNone(run["decision_threshold"])
        self.assertEqual(run["model_sha256"], result.model_sha256)
        self.assertEqual(len(result.model_sha256), 64)

    def test_experimental_threshold_uses_class_one_score_and_persists_alerts(self):
        records = pd.DataFrame(
            {"flow_value": [0.05, 9.95], "protocol_name": ["TCP", "UDP"]}
        )
        model = joblib.load(self.model_path)
        probabilities = np.asarray([[0.35, 0.65], [0.36, 0.64]])

        with (
            patch(
                "seguridad_pymes.inference.THRESHOLD_STUDY_MODEL_PATH",
                self.model_path,
            ),
            patch("seguridad_pymes.inference.load_trained_model", return_value=model),
            patch.object(model, "predict_proba", return_value=probabilities),
            patch.object(
                model,
                "predict",
                side_effect=AssertionError("experimental mode must not call predict"),
            ),
        ):
            result = run_model_analysis(
                records,
                ["boundary-record", "below-threshold-record"],
                source="experimental-model.csv",
                model_path=self.model_path,
                database_path=self.database_path,
                model_id=THRESHOLD_STUDY_MODEL_ID,
            )

        self.assertEqual(result.predictions, (1, 0))
        self.assertEqual(result.attack_scores, (0.65, 0.64))
        self.assertEqual(result.alerts_created, 1)
        self.assertEqual(result.model_id, THRESHOLD_STUDY_MODEL_ID)
        self.assertEqual(result.decision_rule, "predict_proba_gte")
        self.assertEqual(result.decision_threshold, 0.65)
        run = list_analysis_runs(self.database_path)[0]
        self.assertEqual(run["model_id"], THRESHOLD_STUDY_MODEL_ID)
        self.assertEqual(run["decision_threshold"], 0.65)
        self.assertEqual(run["model_sha256"], result.model_sha256)
        alerts = list_alerts(self.database_path)
        self.assertEqual([alert["record_id"] for alert in alerts], ["boundary-record"])
        self.assertEqual(alerts[0]["model_score"], 0.65)

    def test_rejects_experimental_model_id_with_wrong_artifact(self):
        records = pd.DataFrame(
            {"flow_value": [0.05], "protocol_name": ["TCP"]}
        )
        with self.assertRaisesRegex(ValueError, "artefacto autorizado"):
            run_model_analysis(
                records,
                ["record-1"],
                source="wrong-artifact.csv",
                model_path=self.model_path,
                database_path=self.database_path,
                model_id=THRESHOLD_STUDY_MODEL_ID,
            )
        self.assertFalse(self.database_path.exists())

    def test_invalid_experimental_probabilities_mark_run_failed(self):
        records = pd.DataFrame(
            {"flow_value": [0.05], "protocol_name": ["TCP"]}
        )
        model = joblib.load(self.model_path)

        with (
            patch(
                "seguridad_pymes.inference.THRESHOLD_STUDY_MODEL_PATH",
                self.model_path,
            ),
            patch("seguridad_pymes.inference.load_trained_model", return_value=model),
            patch.object(model, "predict_proba", return_value=np.asarray([[np.nan, np.nan]])),
        ):
            with self.assertRaisesRegex(RuntimeError, "probabilidades de ataque inválidas"):
                run_model_analysis(
                    records,
                    ["record-1"],
                    source="invalid-probabilities.csv",
                    model_path=self.model_path,
                    database_path=self.database_path,
                    model_id=THRESHOLD_STUDY_MODEL_ID,
                )

        runs = list_analysis_runs(self.database_path)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["status"], "failed")
        self.assertEqual(runs[0]["model_id"], THRESHOLD_STUDY_MODEL_ID)
        self.assertEqual(runs[0]["decision_threshold"], 0.65)
        self.assertEqual(list_alerts(self.database_path), [])

    def test_invalid_prediction_input_is_rejected_before_run_is_recorded(self):
        with self.assertRaisesRegex(ValueError, "id"):
            run_model_analysis(
                pd.DataFrame(
                    {
                        "flow_value": [1.0],
                        "protocol_name": ["TCP"],
                        "id": [17],
                    }
                ),
                ["record-1"],
                source="unit-test",
                model_path=self.model_path,
                database_path=self.database_path,
            )
        self.assertFalse(self.database_path.exists())

    def test_invalid_input_fails_before_creating_run(self):
        records = pd.DataFrame(
            {
                "flow_value": [float("inf")],
                "protocol_name": ["TCP"],
            }
        )
        with self.assertRaisesRegex(ValueError, "no finitos"):
            run_model_analysis(
                records,
                ["record-1"],
                source="unit-test",
                model_path=self.model_path,
                database_path=self.database_path,
            )
        # This validation happens before creating a run, so no fake execution exists.
        self.assertFalse(self.database_path.exists())

    def test_prediction_failure_is_recorded_as_failed_and_propagated(self):
        records = pd.DataFrame(
            {
                "flow_value": [1.0],
                "protocol_name": ["TCP"],
            }
        )
        with patch("seguridad_pymes.inference.load_trained_model") as load_model:
            model = load_model.return_value
            model.named_steps = {
                "preprocessing": self._trained_preprocessor(),
                "classifier": self._trained_classifier(),
            }
            model.predict.side_effect = RuntimeError("inferencia fallida")
            with self.assertRaisesRegex(RuntimeError, "inferencia fallida"):
                run_model_analysis(
                    records,
                    ["record-1"],
                    source="unit-test",
                    model_path=self.model_path,
                    database_path=self.database_path,
                )
        runs = list_analysis_runs(self.database_path)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["status"], "failed")
        self.assertIn("inferencia fallida", runs[0]["error_message"])

    def _trained_preprocessor(self):
        from seguridad_pymes.training import load_trained_model

        return load_trained_model(self.model_path).named_steps["preprocessing"]

    def _trained_classifier(self):
        from seguridad_pymes.training import load_trained_model

        return load_trained_model(self.model_path).named_steps["classifier"]

    def test_psutil_measurements_for_documented_sample_sizes(self):
        # Fixture artificial solo para probar instrumentación, no para evaluar eficacia.
        csv_path = self.root / "resource-fixture.csv"
        output_path = self.root / "resource-measurements.csv"
        pd.DataFrame(
            {
                "flow_value": [0.05, 0.15, 9.85, 9.95],
                "protocol_name": ["TCP", "TCP", "UDP", "UDP"],
            }
        ).to_csv(csv_path, index=False)

        results = benchmark_inference(
            self.model_path,
            csv_path,
            sample_sizes=(1, 2, 4),
            output_path=output_path,
        )

        self.assertEqual([item.sample_size for item in results], [1, 2, 4])
        self.assertTrue(output_path.is_file())
        self.assertTrue(all(item.elapsed_seconds >= 0 for item in results))
        self.assertTrue(all(item.peak_rss_mib > 0 for item in results))
        measurements = pd.read_csv(output_path)
        self.assertEqual(measurements["sample_size"].tolist(), [1, 2, 4])
        self.assertTrue((measurements["peak_rss_delta_mib"] >= 0).all())

        with self.assertRaises(FileExistsError):
            benchmark_inference(
                self.model_path,
                csv_path,
                sample_sizes=(1,),
                output_path=output_path,
            )


if __name__ == "__main__":
    unittest.main()
