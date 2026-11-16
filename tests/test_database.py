import sqlite3
import tempfile
import unittest
from pathlib import Path

from seguridad_pymes.database import (
    PersistenceError,
    complete_analysis_run,
    create_analysis_run,
    initialize_database,
    list_alerts,
    list_analysis_runs,
    update_alert_review_state,
)


class DatabasePersistenceTests(unittest.TestCase):
    """Comprueba esquema y restricciones usando únicamente una DB temporal."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.database_path = Path(self.temp_dir.name) / "analysis.sqlite3"
        initialize_database(self.database_path)

    def create_completed_run(self):
        run_id = create_analysis_run(
            self.database_path,
            source="unit-test.csv",
            model_reference="test-model.joblib",
            started_at="2026-10-17T12:00:00+00:00",
        )
        count = complete_analysis_run(
            self.database_path,
            run_id,
            record_ids=["flow-1", "flow-2", "flow-3"],
            predictions=[0, 1, 1],
            scores=[0.1, 0.82, None],
            finished_at="2026-10-17T12:00:01+00:00",
        )
        return run_id, count

    def test_persists_run_and_only_positive_class_alerts(self):
        run_id, count = self.create_completed_run()

        runs = list_analysis_runs(self.database_path)
        alerts = list_alerts(self.database_path)

        self.assertEqual(count, 2)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["run_id"], run_id)
        self.assertEqual(runs[0]["status"], "completed")
        self.assertEqual(runs[0]["records_processed"], 3)
        self.assertEqual(runs[0]["alerts_created"], 2)
        self.assertEqual({row["record_id"] for row in alerts}, {"flow-2", "flow-3"})
        self.assertTrue(all(row["predicted_class"] == 1 for row in alerts))
        self.assertEqual(
            {row["review_state"] for row in alerts},
            {"pending"},
        )
        self.assertEqual(
            {row["model_score"] for row in alerts},
            {0.82, None},
        )
        self.assertTrue(all(row["run_id"] == run_id for row in alerts))

    def test_persists_model_decision_metadata(self):
        run_id = create_analysis_run(
            self.database_path,
            source="experimental.csv",
            model_reference="study-model.joblib",
            model_id="threshold_study_random_forest",
            decision_rule="predict_proba_gte",
            decision_threshold=0.65,
            model_sha256="a" * 64,
        )

        run = list_analysis_runs(self.database_path)[0]
        self.assertEqual(run["run_id"], run_id)
        self.assertEqual(run["model_reference"], "study-model.joblib")
        self.assertEqual(run["model_id"], "threshold_study_random_forest")
        self.assertEqual(run["decision_rule"], "predict_proba_gte")
        self.assertEqual(run["decision_threshold"], 0.65)
        self.assertEqual(run["model_sha256"], "a" * 64)

    def test_alert_query_joins_model_rule_threshold_source_and_run_date(self):
        run_id = create_analysis_run(
            self.database_path,
            source="traffic.csv",
            model_reference="study-model.joblib",
            model_id="threshold_study_random_forest",
            decision_rule="predict_proba_gte",
            decision_threshold=0.65,
            model_sha256="b" * 64,
            started_at="2026-10-17T12:00:00+00:00",
        )
        complete_analysis_run(
            self.database_path,
            run_id,
            record_ids=["alert-record"],
            predictions=[1],
            scores=[0.78],
            finished_at="2026-10-17T12:00:01+00:00",
        )

        alert = list_alerts(self.database_path)[0]

        self.assertEqual(alert["record_id"], "alert-record")
        self.assertEqual(alert["source"], "traffic.csv")
        self.assertEqual(alert["model_id"], "threshold_study_random_forest")
        self.assertEqual(alert["model_reference"], "study-model.joblib")
        self.assertEqual(alert["decision_rule"], "predict_proba_gte")
        self.assertEqual(alert["decision_threshold"], 0.65)
        self.assertEqual(alert["model_sha256"], "b" * 64)
        self.assertEqual(alert["run_started_at"], "2026-10-17T12:00:00+00:00")
        self.assertEqual(alert["run_status"], "completed")

    def test_rejects_inconsistent_or_invalid_model_metadata(self):
        arguments = {
            "database_path": self.database_path,
            "source": "invalid.csv",
            "model_reference": "model.joblib",
        }
        with self.assertRaisesRegex(ValueError, "requiere un umbral"):
            create_analysis_run(
                **arguments,
                decision_rule="predict_proba_gte",
            )
        with self.assertRaisesRegex(ValueError, "decision_rule"):
            create_analysis_run(
                **arguments,
                decision_rule="unknown",
            )
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            create_analysis_run(**arguments, model_sha256="not-a-hash")

    def test_review_update_filter_and_bound_parameters(self):
        _, _ = self.create_completed_run()
        alerts = list_alerts(self.database_path)
        alert = alerts[0]

        update_alert_review_state(
            self.database_path, int(alert["alert_id"]), "confirmed"
        )
        false_positive = next(row for row in alerts if row["alert_id"] != alert["alert_id"])
        update_alert_review_state(
            self.database_path, int(false_positive["alert_id"]), "false_positive"
        )

        reviewed = list_alerts(self.database_path, review_state="confirmed")
        self.assertEqual(len(reviewed), 1)
        self.assertEqual(reviewed[0]["review_state"], "confirmed")
        false_positives = list_alerts(
            self.database_path, review_state="false_positive"
        )
        self.assertEqual(len(false_positives), 1)
        self.assertEqual(false_positives[0]["alert_id"], false_positive["alert_id"])
        self.assertEqual(
            {
                row["alert_id"]: row["review_state"]
                for row in list_alerts(self.database_path)
            },
            {
                row["alert_id"]: (
                    "confirmed"
                    if row["alert_id"] == alert["alert_id"]
                    else (
                        "false_positive"
                        if row["alert_id"] == false_positive["alert_id"]
                        else "pending"
                    )
                )
                for row in alerts
            },
        )
        initialize_database(self.database_path)
        self.assertEqual(
            next(
                row
                for row in list_alerts(self.database_path)
                if row["alert_id"] == alert["alert_id"]
            )["review_state"],
            "confirmed",
        )
        self.assertEqual(
            next(
                row
                for row in list_alerts(self.database_path)
                if row["alert_id"] == false_positive["alert_id"]
            )["review_state"],
            "false_positive",
        )
        self.assertEqual(
            list_alerts(self.database_path, run_id="' OR 1=1 --"),
            [],
        )

    def test_migrates_legacy_confirmed_attack_without_duplicating_alerts(self):
        legacy_database_path = Path(self.temp_dir.name) / "legacy.sqlite3"
        run_id = "legacy-run"
        connection = sqlite3.connect(legacy_database_path)
        try:
            connection.executescript(
                """
                CREATE TABLE analysis_runs (
                    run_id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    source TEXT NOT NULL,
                    model_reference TEXT NOT NULL,
                    status TEXT NOT NULL,
                    records_processed INTEGER NOT NULL DEFAULT 0,
                    alerts_created INTEGER NOT NULL DEFAULT 0,
                    error_message TEXT
                );
                CREATE TABLE alerts (
                    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    predicted_class INTEGER NOT NULL,
                    model_score REAL,
                    review_state TEXT NOT NULL DEFAULT 'pending'
                        CHECK (review_state IN (
                            'pending', 'confirmed_attack', 'false_positive'
                        )),
                    FOREIGN KEY (run_id) REFERENCES analysis_runs(run_id),
                    UNIQUE (run_id, record_id)
                );
                INSERT INTO analysis_runs VALUES (
                    'legacy-run', '2026-10-17T12:00:00+00:00',
                    '2026-10-17T12:00:01+00:00', 'legacy.csv', 'model',
                    'completed', 1, 1, NULL
                );
                INSERT INTO alerts VALUES (
                    14, 'legacy-run', 'flow-legacy',
                    '2026-10-17T12:00:01+00:00', 1, 0.9, 'confirmed_attack'
                );
                """
            )
            connection.commit()
        finally:
            connection.close()

        initialize_database(legacy_database_path)
        alerts = list_alerts(legacy_database_path)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_id"], 14)
        self.assertEqual(alerts[0]["record_id"], "flow-legacy")
        self.assertEqual(alerts[0]["review_state"], "confirmed")
        self.assertEqual(alerts[0]["source"], "legacy.csv")
        self.assertIsNone(alerts[0]["model_id"])
        self.assertIsNone(alerts[0]["decision_rule"])
        self.assertIsNone(alerts[0]["decision_threshold"])
        self.assertIsNone(alerts[0]["model_sha256"])
        initialize_database(legacy_database_path)
        legacy_runs = list_analysis_runs(legacy_database_path)
        self.assertEqual(len(legacy_runs), 1)
        self.assertEqual(legacy_runs[0]["model_reference"], "model")
        self.assertIsNone(legacy_runs[0]["model_id"])
        self.assertIsNone(legacy_runs[0]["decision_rule"])
        self.assertIsNone(legacy_runs[0]["decision_threshold"])
        self.assertIsNone(legacy_runs[0]["model_sha256"])
        self.assertEqual(len(list_alerts(legacy_database_path)), 1)

    def test_database_constraints_reject_invalid_alert_and_foreign_key(self):
        run_id, _ = self.create_completed_run()

        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO alerts
                        (run_id, record_id, detected_at, predicted_class, model_score)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (run_id, "normal-flow", "2026-10-17T12:00:00+00:00", 0, 0.1),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO alerts
                        (run_id, record_id, detected_at, predicted_class, model_score)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    ("unknown-run", "attack-flow", "2026-10-17T12:00:00+00:00", 1, 0.9),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO alerts
                        (run_id, record_id, detected_at, predicted_class, model_score)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (run_id, "duplicate-attack", "2026-10-17T12:00:00+00:00", 1, 1.1),
                )
        finally:
            connection.close()

    def test_rejects_duplicate_record_ids_and_invalid_scores(self):
        run_id = create_analysis_run(
            self.database_path,
            source="unit-test",
            model_reference="model",
        )
        with self.assertRaisesRegex(ValueError, "únicos"):
            complete_analysis_run(
                self.database_path,
                run_id,
                record_ids=["same", "same"],
                predictions=[1, 1],
                scores=[0.8, 0.9],
            )

        with self.assertRaisesRegex(ValueError, "finitos y estar entre 0 y 1"):
            complete_analysis_run(
                self.database_path,
                run_id,
                record_ids=["flow"],
                predictions=[1],
                scores=[1.2],
            )
        with self.assertRaisesRegex(ValueError, "finitos y estar entre 0 y 1"):
            complete_analysis_run(
                self.database_path,
                run_id,
                record_ids=["flow"],
                predictions=[1],
                scores=[float("nan")],
            )
        self.assertEqual(list_analysis_runs(self.database_path)[0]["status"], "running")

    def test_surfaces_database_failures(self):
        with self.assertRaises(PersistenceError):
            list_alerts(self.database_path.parent / "missing" / "db.sqlite3")


if __name__ == "__main__":
    unittest.main()
