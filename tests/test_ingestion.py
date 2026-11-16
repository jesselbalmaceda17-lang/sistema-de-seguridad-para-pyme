import csv
import tempfile
import unittest
from pathlib import Path

import numpy as np

from seguridad_pymes.ingestion import (
    DatasetValidationError,
    load_unsw_nb15,
    prepare_unsw_nb15,
)


class UnswNb15IngestionTests(unittest.TestCase):
    """Prueba reglas de carga con CSV temporales, no con datos de eficacia."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.train_path = self.root / "training.csv"
        self.test_path = self.root / "testing.csv"
        self.header = ("id", "flow_measure", "protocol_name", "label", "attack_cat")

    def write_csv(self, path, header, rows):
        with path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(header)
            writer.writerows(rows)

    def write_standard_splits(self):
        self.write_csv(
            self.train_path,
            self.header,
            [
                (1, 1, "TCP", 0, "Normal"),
                (2, 3, "UDP", 1, "DoS"),
                (3, 5, "TCP", 1, "DoS"),
                (3, 5, "TCP", 1, "DoS"),
                (4, "", "TCP", 0, "Normal"),
                (5, 6, "TCP", 2, "DoS"),
            ],
        )
        self.write_csv(
            self.test_path,
            self.header,
            [
                (10, 2, "TCP", 0, "Normal"),
                (11, 100, "QUIC", 1, "Generic"),
                (12, "invalid", "UDP", 1, "DoS"),
                (13, 3, "", 0, "Normal"),
                (14, 4, "TCP", "not_binary", "Normal"),
                (15, 1, "TCP", 0, "Normal"),
                (15, 1, "TCP", 0, "Normal"),
            ],
        )

    def test_validates_rows_excludes_leakage_and_reports_unseen_categories(self):
        self.write_standard_splits()

        dataset = load_unsw_nb15(self.train_path, self.test_path)

        self.assertEqual(dataset.X_train.columns.tolist(), ["flow_measure", "protocol_name"])
        self.assertEqual(dataset.excluded_columns, ("id", "label", "attack_cat"))
        self.assertEqual(dataset.numeric_columns, ("flow_measure",))
        self.assertEqual(dataset.categorical_columns, ("protocol_name",))
        self.assertEqual(dataset.y_train.tolist(), [0, 1, 1])
        self.assertEqual(dataset.y_test.tolist(), [0, 1, 0])
        self.assertEqual(
            dataset.train_report.dropped_by_reason,
            {
                "duplicate_rows": 1,
                "rows_with_missing_values": 1,
                "invalid_binary_label": 1,
                "invalid_numeric_values": 0,
            },
        )
        self.assertEqual(
            dataset.test_report.dropped_by_reason,
            {
                "duplicate_rows": 1,
                "rows_with_missing_values": 1,
                "invalid_binary_label": 1,
                "invalid_numeric_values": 1,
            },
        )
        self.assertEqual(dataset.test_report.unseen_test_categories, {"protocol_name": 1})
        self.assertEqual(dataset.train_report.rows_dropped, 3)
        self.assertEqual(dataset.test_report.rows_dropped, 4)

    def test_preprocessing_fits_on_train_and_ignores_unseen_test_categories(self):
        self.write_standard_splits()

        prepared = prepare_unsw_nb15(self.train_path, self.test_path)

        transformer = prepared.preprocessing_pipeline.named_steps["features"]
        numeric_scaler = transformer.named_transformers_["numeric"]
        self.assertEqual(numeric_scaler.mean_.tolist(), [3.0])
        self.assertEqual(prepared.X_train.shape[0], 3)
        self.assertEqual(prepared.X_test.shape[0], 3)
        self.assertEqual(prepared.X_train.shape[1], prepared.X_test.shape[1])
        transformed_test = (
            prepared.X_test.toarray()
            if hasattr(prepared.X_test, "toarray")
            else prepared.X_test
        )
        self.assertTrue(np.isfinite(np.asarray(transformed_test)).all())

    def test_rejects_different_train_and_test_headers(self):
        self.write_csv(self.train_path, self.header, [(1, 1, "TCP", 0, "Normal")])
        self.write_csv(
            self.test_path,
            ("id", "protocol_name", "flow_measure", "label", "attack_cat"),
            [(2, "TCP", 1, 0, "Normal")],
        )

        with self.assertRaisesRegex(DatasetValidationError, "mismos nombres y orden"):
            load_unsw_nb15(self.train_path, self.test_path)

    def test_rejects_duplicate_header_names(self):
        self.write_csv(
            self.train_path,
            ("id", "flow_measure", "flow_measure", "label"),
            [(1, 1, 2, 0)],
        )

        with self.assertRaisesRegex(DatasetValidationError, "duplicados"):
            load_unsw_nb15(self.train_path, self.test_path)


if __name__ == "__main__":
    unittest.main()
