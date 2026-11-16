import csv
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

from seguridad_pymes.evaluation import evaluate_model
from seguridad_pymes.training import train_random_forest


class ReservedTestEvaluationTests(unittest.TestCase):
    """Pruebas de cómputo y archivos, no evidencia de eficacia del modelo."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.train_path = self.root / "training.csv"
        self.test_path = self.root / "testing.csv"
        self.model_path = self.root / "model.joblib"
        self.output_dir = self.root / "results"

    @staticmethod
    def write_csv(path, header, rows):
        with path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(header)
            writer.writerows(rows)

    def set_up_trained_artifact(self):
        train_rows = []
        for index in range(20):
            label = index % 2
            train_rows.append(
                (
                    index,
                    float(label * 10 + index / 100),
                    "UDP" if label else "TCP",
                    label,
                    "DoS" if label else "Normal",
                )
            )
        header = ("id", "flow_measure", "protocol", "label", "attack_cat")
        self.write_csv(self.train_path, header, train_rows)
        train_random_forest(
            self.train_path,
            self.model_path,
            random_state=11,
            cv_splits=2,
            search_iterations=1,
        )

    def test_evaluates_holdout_saves_metrics_csv_and_svg_without_fitting(self):
        self.set_up_trained_artifact()
        header = ("id", "flow_measure", "protocol", "label", "attack_cat")
        test_rows = [
            (101, 0.1, "TCP", 0, "Normal"),
            (102, 0.2, "UDP", 0, "Normal"),
            (103, 9.8, "UDP", 1, "DoS"),
            (104, 10.1, "TCP", 1, "DoS"),
            (101, 0.1, "TCP", 0, "Normal"),
            (105, "", "TCP", 1, "DoS"),
        ]
        self.write_csv(self.test_path, header, test_rows)
        model_mtime = self.model_path.stat().st_mtime_ns
        self.train_path.unlink()

        result = evaluate_model(
            model_path=self.model_path,
            test_path=self.test_path,
            output_dir=self.output_dir,
        )

        self.assertEqual(result.evaluated_samples, 4)
        self.assertEqual(result.test_report.rows_read, 6)
        self.assertEqual(result.test_report.rows_dropped, 2)
        self.assertEqual(result.test_report.dropped_by_reason["duplicate_rows"], 1)
        self.assertEqual(
            result.test_report.dropped_by_reason["rows_with_missing_values"], 1
        )
        self.assertEqual(self.model_path.stat().st_mtime_ns, model_mtime)
        self.assertGreaterEqual(result.inference_time_seconds, 0)
        self.assertAlmostEqual(
            sum(sum(row) for row in result.confusion_matrix),
            result.evaluated_samples,
        )
        tn, fp = result.confusion_matrix[0]
        fn, tp = result.confusion_matrix[1]
        self.assertAlmostEqual(
            result.precision, tp / (tp + fp) if tp + fp else 0.0
        )
        self.assertAlmostEqual(
            result.recall, tp / (tp + fn) if tp + fn else 0.0
        )
        self.assertAlmostEqual(result.false_positive_rate, fp / (fp + tn))

        for artifact in (
            result.metrics_path,
            result.confusion_matrix_path,
            result.confusion_matrix_plot_path,
            result.metrics_plot_path,
        ):
            self.assertTrue(artifact.is_file())
            self.assertGreater(artifact.stat().st_size, 0)

        metrics = json.loads(result.metrics_path.read_text(encoding="utf-8"))
        self.assertEqual(metrics["evaluated_samples"], 4)
        self.assertIn("test_file_sha256", metrics["files"])
        self.assertIn("training_metadata_sha256", metrics["files"])
        self.assertIn("scikit_learn", metrics["library_versions"])
        self.assertFalse(metrics["methodology"]["test_set_used_for_training_or_tuning"])
        self.assertFalse(metrics["methodology"]["pipeline_fitted_during_evaluation"])
        self.assertIn("inference_time_seconds", metrics["metrics"])
        self.assertIn("false_positive_rate", metrics["limitations"])

        confusion_csv = pd.read_csv(result.confusion_matrix_path, index_col=0)
        csv_matrix = confusion_csv.to_numpy(dtype=int)
        expected_matrix = np.asarray(result.confusion_matrix)
        np.testing.assert_array_equal(csv_matrix, expected_matrix)

        predictions_svg = result.metrics_plot_path.read_text(encoding="utf-8")
        self.assertIn("<svg", predictions_svg)
        self.assertIn("Recall (ataque)", predictions_svg)

    def test_refuses_test_partition_without_both_classes(self):
        self.set_up_trained_artifact()
        self.write_csv(
            self.test_path,
            ("id", "flow_measure", "protocol", "label", "attack_cat"),
            [
                (1, 0.1, "TCP", 0, "Normal"),
                (2, 0.2, "UDP", 0, "Normal"),
            ],
        )

        with self.assertRaisesRegex(ValueError, "ambas clases"):
            evaluate_model(self.model_path, self.test_path, self.output_dir)

    def test_refuses_to_overwrite_existing_evaluation_outputs(self):
        self.set_up_trained_artifact()
        self.output_dir.mkdir()
        existing = self.output_dir / "metrics.json"
        existing.write_text("existing result", encoding="utf-8")

        with self.assertRaisesRegex(FileExistsError, "no sobrescribe"):
            evaluate_model(self.model_path, self.test_path, self.output_dir)

        self.assertEqual(existing.read_text(encoding="utf-8"), "existing result")


if __name__ == "__main__":
    unittest.main()
