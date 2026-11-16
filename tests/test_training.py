import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd
from sklearn.pipeline import Pipeline

from seguridad_pymes.training import (
    _sample_training_dataset,
    load_trained_model,
    train_random_forest,
)
from seguridad_pymes.ingestion import load_unsw_training


class RandomForestTrainingTests(unittest.TestCase):
    """Pruebas funcionales pequeñas; no son evidencia de eficacia del modelo."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.train_path = self.root / "training.csv"
        self.model_path = self.root / "model.joblib"

    def write_training_csv(self):
        rows = []
        for index in range(40):
            label = index % 2
            rows.append(
                (
                    index,
                    index * 0.5 + label * 2,
                    "UDP" if label else "TCP",
                    label,
                    "DoS" if label else "Normal",
                )
            )
        with self.train_path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(("id", "flow_measure", "protocol", "label", "attack_cat"))
            writer.writerows(rows)

    def test_train_save_load_predict_without_opening_test_file(self):
        self.write_training_csv()

        result = train_random_forest(
            train_path=self.train_path,
            model_path=self.model_path,
            random_state=7,
            cv_splits=2,
            search_iterations=1,
        )

        self.assertTrue(result.model_path.is_file())
        self.assertTrue(result.metadata_path.is_file())
        self.assertEqual(result.training_rows, 40)
        self.assertEqual(result.training_class_counts, {0: 20, 1: 20})
        model = load_trained_model(result.model_path)
        self.assertIsInstance(model, Pipeline)
        self.assertEqual(list(model.named_steps), ["preprocessing", "classifier"])

        predictions = model.predict(
            pd.DataFrame(
                {
                    "flow_measure": [0.0, 7.0],
                    "protocol": ["TCP", "UDP"],
                }
            )
        )
        self.assertEqual(predictions.shape, (2,))

        metadata = json.loads(result.metadata_path.read_text(encoding="utf-8"))
        self.assertFalse(metadata["dataset"]["test_file_used"])
        self.assertEqual(metadata["training"]["random_state"], 7)
        self.assertEqual(metadata["training"]["cv"]["n_splits"], 2)
        self.assertEqual(metadata["training"]["data_quality"]["rows_kept"], 40)
        self.assertEqual(
            metadata["training"]["classifier_parameters"]["n_jobs"], 1
        )
        self.assertIn("scikit_learn", metadata["libraries"])
        self.assertIn("flow_measure", metadata["features"]["input_predictors"])
        self.assertNotIn("attack_cat", metadata["features"]["input_predictors"])

    def test_pilot_sample_is_stratified_reproducible_and_exact_size(self):
        self.write_training_csv()
        dataset = load_unsw_training(self.train_path)

        first, first_counts = _sample_training_dataset(dataset, 20, 42)
        second, second_counts = _sample_training_dataset(dataset, 20, 42)

        self.assertEqual(len(first.X_train), 20)
        self.assertEqual(first_counts, {0: 10, 1: 10})
        self.assertEqual(second_counts, first_counts)
        pd.testing.assert_frame_equal(first.X_train, second.X_train)
        pd.testing.assert_series_equal(first.y_train, second.y_train)

    def test_pilot_records_sample_and_never_opens_test_file(self):
        self.write_training_csv()
        test_path = self.root / "UNSW_NB15_testing-set.csv"
        test_path.write_text("should,never,be,read\n", encoding="utf-8")
        pilot_model_path = self.root / "models" / "unsw_nb15_random_forest_pilot.joblib"
        original_open = Path.open

        def guarded_open(path, *args, **kwargs):
            if path == test_path:
                raise AssertionError("El archivo oficial de prueba no debe abrirse.")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", guarded_open):
            result = train_random_forest(
                train_path=self.train_path,
                model_path=pilot_model_path,
                profile="pilot",
                sample_rows=20,
                random_state=42,
            )

        metadata = json.loads(result.metadata_path.read_text(encoding="utf-8"))
        training = metadata["training"]
        self.assertEqual(result.model_path, pilot_model_path)
        self.assertEqual(training["profile"], "pilot")
        self.assertEqual(training["rows_original"], 40)
        self.assertEqual(training["rows_valid_after_cleaning"], 40)
        self.assertEqual(training["rows_selected_for_training"], 20)
        self.assertEqual(training["class_counts_validated"], {"0": 20, "1": 20})
        self.assertEqual(training["class_counts_selected"], {"0": 10, "1": 10})
        self.assertEqual(training["sample_random_state"], 42)
        self.assertEqual(training["cv"]["n_splits"], 2)
        self.assertEqual(training["search_iterations"], 2)
        self.assertEqual(training["training_time_scope"], "RandomizedSearchCV.fit, including CV and refit")
        self.assertGreaterEqual(training["training_time_seconds"], 0)
        self.assertEqual(len(training["parameters_tested"]), 2)
        self.assertTrue(all(
            item["parameters"]["classifier__min_samples_leaf"] == 2
            and item["parameters"]["classifier__max_features"] == "sqrt"
            and item["parameters"]["classifier__n_estimators"] in (50, 80)
            and item["parameters"]["classifier__max_depth"] in (16, 24)
            for item in training["parameters_tested"]
        ))
        self.assertFalse(metadata["dataset"]["test_file_used"])

    def test_pilot_profile_protects_definitive_model_filename(self):
        self.write_training_csv()

        with self.assertRaisesRegex(ValueError, "proteger el modelo definitivo"):
            train_random_forest(
                train_path=self.train_path,
                model_path=self.root / "unsw_nb15_random_forest.joblib",
                profile="pilot",
                sample_rows=20,
            )

    def test_final_fixed_uses_all_training_rows_and_pilot_selected_parameters(self):
        self.write_training_csv()
        test_path = self.root / "UNSW_NB15_testing-set.csv"
        test_path.write_text("must,not,be,opened\n", encoding="utf-8")
        final_model_path = self.root / "models" / "unsw_nb15_random_forest.joblib"
        original_open = Path.open

        def guarded_open(path, *args, **kwargs):
            if path == test_path:
                raise AssertionError("El archivo de prueba no debe abrirse.")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", guarded_open):
            result = train_random_forest(
                train_path=self.train_path,
                model_path=final_model_path,
                profile="final-fixed",
                random_state=42,
            )

        metadata = json.loads(result.metadata_path.read_text(encoding="utf-8"))
        training = metadata["training"]
        self.assertEqual(result.training_rows, 40)
        self.assertEqual(result.training_class_counts, {0: 20, 1: 20})
        self.assertEqual(result.best_params, {
            "classifier__n_estimators": 80,
            "classifier__max_depth": 24,
            "classifier__min_samples_leaf": 2,
            "classifier__max_features": "sqrt",
        })
        self.assertIsNone(result.best_cv_f1)
        self.assertIsNone(result.cv_splits)
        self.assertEqual(training["profile"], "final-fixed")
        self.assertEqual(training["rows_original"], 40)
        self.assertEqual(training["rows_valid_after_cleaning"], 40)
        self.assertEqual(training["rows_selected_for_training"], 40)
        self.assertEqual(training["class_counts_validated"], {"0": 20, "1": 20})
        self.assertEqual(training["best_parameters"], result.best_params)
        self.assertEqual(training["random_state"], 42)
        self.assertEqual(training["training_time_scope"], "Pipeline.fit on all validated training rows")
        self.assertGreaterEqual(training["training_time_seconds"], 0)
        self.assertEqual(
            training["hyperparameter_selection"]["method"],
            "StratifiedKFold cross-validation",
        )
        self.assertEqual(
            training["hyperparameter_selection"]["source_dataset"],
            "stratified pilot sample from official training split",
        )
        self.assertIn("pilot", training["hyperparameter_selection"]["provenance"])
        self.assertIsNone(training["best_mean_cv_f1"])
        self.assertFalse(metadata["dataset"]["test_file_used"])
        self.assertIn("scikit_learn", metadata["libraries"])
        model = load_trained_model(result.model_path)
        classifier = model.named_steps["classifier"]
        self.assertEqual(classifier.n_estimators, 80)
        self.assertEqual(classifier.max_depth, 24)
        self.assertEqual(classifier.min_samples_leaf, 2)
        self.assertEqual(classifier.max_features, "sqrt")
        self.assertEqual(classifier.random_state, 42)
        self.assertEqual(classifier.n_jobs, 1)

    def test_final_fixed_refuses_to_overwrite_existing_artifact(self):
        self.write_training_csv()
        final_model_path = self.root / "unsw_nb15_random_forest.joblib"
        original_bytes = b"existing-final-artifact"
        final_model_path.write_bytes(original_bytes)

        with self.assertRaisesRegex(FileExistsError, "no sobrescribe"):
            train_random_forest(
                train_path=self.train_path,
                model_path=final_model_path,
                profile="final-fixed",
            )

        self.assertEqual(final_model_path.read_bytes(), original_bytes)

    def test_rejects_training_with_only_one_class(self):
        with self.train_path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(("flow_measure", "label"))
            writer.writerows((index, 0) for index in range(4))

        with self.assertRaisesRegex(ValueError, "ambas clases binarias"):
            train_random_forest(
                train_path=self.train_path,
                model_path=self.model_path,
                cv_splits=2,
                search_iterations=1,
            )

    def test_refuses_to_overwrite_existing_model(self):
        self.write_training_csv()
        original_bytes = b"existing-user-artifact"
        self.model_path.write_bytes(original_bytes)

        with self.assertRaisesRegex(FileExistsError, "no sobrescribe"):
            train_random_forest(
                train_path=self.train_path,
                model_path=self.model_path,
                cv_splits=2,
                search_iterations=1,
            )

        self.assertEqual(self.model_path.read_bytes(), original_bytes)


if __name__ == "__main__":
    unittest.main()
