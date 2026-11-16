import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import joblib
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline

from seguridad_pymes.ingestion import load_unsw_training
from seguridad_pymes.threshold_analysis import (
    THRESHOLDS,
    compute_threshold_metrics,
    extract_attack_scores,
    run_threshold_study,
    select_threshold,
    split_training_data,
)


class ThresholdAnalysisTests(unittest.TestCase):
    """Small synthetic fixtures test methodology and wiring, not model efficacy."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.train_path = self.root / "training.csv"
        self.test_path = self.root / "UNSW_NB15_testing-set.csv"
        self.output_dir = self.root / "threshold-study"

    def write_training_csv(self, rows=60):
        with self.train_path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(("id", "flow_measure", "protocol", "label", "attack_cat"))
            for index in range(rows):
                label = index % 2
                writer.writerow(
                    (
                        index,
                        float(label * 10 + index / 100),
                        "UDP" if label else "TCP",
                        label,
                        "DoS" if label else "Normal",
                    )
                )

    def test_split_is_stratified_reproducible_and_disjoint(self):
        self.write_training_csv()
        dataset = load_unsw_training(self.train_path)
        first = split_training_data(dataset)
        second = split_training_data(dataset)

        X_train, X_validation, y_train, y_validation = first
        self.assertEqual(len(X_train), 48)
        self.assertEqual(len(X_validation), 12)
        self.assertEqual(y_train.value_counts().to_dict(), {0: 24, 1: 24})
        self.assertEqual(y_validation.value_counts().to_dict(), {0: 6, 1: 6})
        self.assertTrue(set(X_train.index).isdisjoint(X_validation.index))
        pd.testing.assert_frame_equal(X_train, second[0])
        pd.testing.assert_frame_equal(X_validation, second[1])
        pd.testing.assert_series_equal(y_train, second[2])
        pd.testing.assert_series_equal(y_validation, second[3])

    def test_threshold_metrics_and_selection_follow_declared_rules(self):
        result = compute_threshold_metrics(
            [0, 0, 1, 1],
            [0.2, 0.8, 0.7, 0.9],
            0.5,
        )
        self.assertEqual(
            (result["tn"], result["fp"], result["fn"], result["tp"]),
            (1, 1, 0, 2),
        )
        self.assertAlmostEqual(result["precision"], 2 / 3)
        self.assertEqual(result["recall"], 1.0)
        self.assertAlmostEqual(result["f1"], 0.8)
        self.assertEqual(result["fpr"], 0.5)
        self.assertEqual(result["alerts"], 3)
        self.assertEqual(THRESHOLDS[0], 0.5)
        self.assertEqual(THRESHOLDS[-1], 0.95)
        self.assertEqual(len(THRESHOLDS), 10)

        candidates = [
            {"threshold": 0.5, "recall": 0.96, "fpr": 0.2},
            {"threshold": 0.6, "recall": 0.97, "fpr": 0.2},
            {"threshold": 0.7, "recall": 0.96, "fpr": 0.2},
            {"threshold": 0.8, "recall": 0.94, "fpr": 0.01},
        ]
        self.assertEqual(select_threshold(candidates), 0.6)
        self.assertIsNone(
            select_threshold(
                [{"threshold": 0.5, "recall": 0.94, "fpr": 0.1}]
            )
        )

    def test_extracts_attack_score_using_classifier_class_order(self):
        class ScorePipeline:
            named_steps = {
                "classifier": type(
                    "Classifier", (), {"classes_": np.array([1, 0])}
                )()
            }

            def predict_proba(self, records):
                return np.tile([0.8, 0.2], (len(records), 1))

        scores = extract_attack_scores(
            ScorePipeline(), pd.DataFrame({"x": [1, 2]})
        )
        np.testing.assert_array_equal(scores, [0.8, 0.8])

    def test_study_writes_separate_artifacts_without_opening_official_test(self):
        self.write_training_csv()
        self.test_path.write_text("must,not,be,opened\n", encoding="utf-8")
        original_open = Path.open

        def guarded_open(path, *args, **kwargs):
            if path == self.test_path:
                raise AssertionError("The official test file must not be opened.")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", guarded_open):
            result = run_threshold_study(self.train_path, self.output_dir)

        model = joblib.load(result.model_path)
        self.assertIsInstance(model, Pipeline)
        self.assertEqual(
            model.named_steps["preprocessing"]
            .named_transformers_["numeric"]
            .n_samples_seen_,
            result.training_rows,
        )
        self.assertEqual(result.training_rows, 48)
        self.assertEqual(result.validation_rows, 12)
        self.assertTrue(result.model_metadata_path.is_file())
        self.assertTrue(result.results_path.is_file())
        self.assertTrue(result.report_path.is_file())
        metadata = json.loads(result.model_metadata_path.read_text(encoding="utf-8"))
        report = json.loads(result.report_path.read_text(encoding="utf-8"))
        self.assertFalse(metadata["dataset"]["test_file_used"])
        self.assertEqual(metadata["split"]["random_state"], 42)
        self.assertEqual(metadata["model"]["training_time_scope"], "Pipeline.fit on training partition only")
        self.assertEqual(len(report["threshold_metrics"]), 10)
        self.assertEqual(report["selection_rule"], metadata["methodology"]["selection_rule"])
        self.assertIn("training_file_sha256", report)
        self.assertIn("model_sha256", report)
        self.assertIn("threshold_results_sha256", report)

        second_output = self.root / "threshold-study-second-run"
        second = run_threshold_study(self.train_path, second_output)
        self.assertEqual(
            result.results_path.read_bytes(),
            second.results_path.read_bytes(),
        )
        self.assertEqual(result.selected_threshold, second.selected_threshold)

    def test_refuses_existing_output_directory_without_changing_contents(self):
        self.write_training_csv()
        self.output_dir.mkdir()
        existing = self.output_dir / "keep.txt"
        existing.write_text("existing", encoding="utf-8")

        with self.assertRaisesRegex(FileExistsError, "no se sobrescribirá"):
            run_threshold_study(self.train_path, self.output_dir)

        self.assertEqual(existing.read_text(encoding="utf-8"), "existing")
        self.assertEqual(list(self.output_dir.iterdir()), [existing])


if __name__ == "__main__":
    unittest.main()
