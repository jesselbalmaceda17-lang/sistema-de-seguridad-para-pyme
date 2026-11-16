"""Persistencia SQLite local para ejecuciones y alertas generadas por inferencia."""

from __future__ import annotations

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
import math
from pathlib import Path
from typing import Iterator, Sequence


DEFAULT_DATABASE_PATH = Path("data/processed/security_analysis.sqlite3")
REVIEW_STATES = frozenset({"pending", "confirmed", "false_positive"})

SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis_runs (
    run_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    source TEXT NOT NULL CHECK (length(trim(source)) > 0),
    model_reference TEXT NOT NULL CHECK (length(trim(model_reference)) > 0),
    model_id TEXT,
    decision_rule TEXT CHECK (
        decision_rule IS NULL OR decision_rule IN ('predict', 'predict_proba_gte')
    ),
    decision_threshold REAL CHECK (
        decision_threshold IS NULL OR
        (decision_threshold >= 0 AND decision_threshold <= 1)
    ),
    model_sha256 TEXT CHECK (
        model_sha256 IS NULL OR
        (length(model_sha256) = 64 AND model_sha256 NOT GLOB '*[^0-9a-f]*')
    ),
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    records_processed INTEGER NOT NULL DEFAULT 0 CHECK (records_processed >= 0),
    alerts_created INTEGER NOT NULL DEFAULT 0 CHECK (alerts_created >= 0),
    error_message TEXT,
    CHECK (
        (status = 'running' AND finished_at IS NULL)
        OR (status IN ('completed', 'failed') AND finished_at IS NOT NULL)
    ),
    CHECK (alerts_created <= records_processed)
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    record_id TEXT NOT NULL CHECK (length(trim(record_id)) > 0),
    detected_at TEXT NOT NULL,
    predicted_class INTEGER NOT NULL CHECK (predicted_class = 1),
    model_score REAL CHECK (model_score IS NULL OR (model_score >= 0 AND model_score <= 1)),
    review_state TEXT NOT NULL DEFAULT 'pending'
        CHECK (review_state IN ('pending', 'confirmed', 'false_positive')),
    FOREIGN KEY (run_id) REFERENCES analysis_runs(run_id) ON DELETE RESTRICT,
    UNIQUE (run_id, record_id)
);

CREATE INDEX IF NOT EXISTS idx_analysis_runs_started_at
    ON analysis_runs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_detected_at
    ON alerts(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_review_state
    ON alerts(review_state);

CREATE TRIGGER IF NOT EXISTS alerts_require_completed_run
BEFORE INSERT ON alerts
FOR EACH ROW
WHEN (SELECT status FROM analysis_runs WHERE run_id = NEW.run_id) != 'completed'
BEGIN
    SELECT RAISE(ABORT, 'alerts require a completed analysis run');
END;
"""


class PersistenceError(RuntimeError):
    """Error explícito al inicializar o modificar la base SQLite."""


def _migrate_analysis_run_model_metadata(
    connection: sqlite3.Connection,
) -> None:
    columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(analysis_runs)").fetchall()
    }
    additions = {
        "model_id": "TEXT",
        "decision_rule": (
            "TEXT CHECK (decision_rule IS NULL OR "
            "decision_rule IN ('predict', 'predict_proba_gte'))"
        ),
        "decision_threshold": (
            "REAL CHECK (decision_threshold IS NULL OR "
            "(decision_threshold >= 0 AND decision_threshold <= 1))"
        ),
        "model_sha256": (
            "TEXT CHECK (model_sha256 IS NULL OR "
            "(length(model_sha256) = 64 AND "
            "model_sha256 NOT GLOB '*[^0-9a-f]*'))"
        ),
    }
    missing = [
        (name, declaration)
        for name, declaration in additions.items()
        if name not in columns
    ]
    if not missing:
        return
    if not connection.in_transaction:
        connection.execute("BEGIN IMMEDIATE")
    for name, declaration in missing:
        connection.execute(
            f"ALTER TABLE analysis_runs ADD COLUMN {name} {declaration}"
        )


def _migrate_legacy_review_states(connection: sqlite3.Connection) -> None:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'alerts'"
    ).fetchone()
    if row is None or "'confirmed_attack'" not in row["sql"]:
        return

    connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        """
        CREATE TABLE alerts_new (
            alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            record_id TEXT NOT NULL CHECK (length(trim(record_id)) > 0),
            detected_at TEXT NOT NULL,
            predicted_class INTEGER NOT NULL CHECK (predicted_class = 1),
            model_score REAL CHECK (
                model_score IS NULL OR (model_score >= 0 AND model_score <= 1)
            ),
            review_state TEXT NOT NULL DEFAULT 'pending'
                CHECK (review_state IN ('pending', 'confirmed', 'false_positive')),
            FOREIGN KEY (run_id) REFERENCES analysis_runs(run_id) ON DELETE RESTRICT,
            UNIQUE (run_id, record_id)
        )
        """
    )
    connection.execute(
        """
        INSERT INTO alerts_new
            (alert_id, run_id, record_id, detected_at, predicted_class,
             model_score, review_state)
        SELECT alert_id, run_id, record_id, detected_at, predicted_class,
               model_score,
               CASE review_state
                   WHEN 'confirmed_attack' THEN 'confirmed'
                   ELSE review_state
               END
        FROM alerts
        """
    )
    connection.execute("DROP TABLE alerts")
    connection.execute("ALTER TABLE alerts_new RENAME TO alerts")
    connection.execute(
        "CREATE INDEX idx_alerts_detected_at ON alerts(detected_at DESC)"
    )
    connection.execute(
        "CREATE INDEX idx_alerts_review_state ON alerts(review_state)"
    )
    connection.execute(
        """
        CREATE TRIGGER alerts_require_completed_run
        BEFORE INSERT ON alerts
        FOR EACH ROW
        WHEN (SELECT status FROM analysis_runs WHERE run_id = NEW.run_id) != 'completed'
        BEGIN
            SELECT RAISE(ABORT, 'alerts require a completed analysis run');
        END
        """
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def _connect(database_path: str | Path) -> Iterator[sqlite3.Connection]:
    path = Path(database_path)
    try:
        if str(database_path) != ":memory:":
            path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
    except (OSError, sqlite3.Error) as error:
        raise PersistenceError(
            f"No se pudo abrir la base SQLite {database_path}: {error}"
        ) from error
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database(
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> Path:
    """Crea las tablas e índices si no existen; no borra datos existentes."""

    try:
        with _connect(database_path) as connection:
            connection.executescript(SCHEMA)
            _migrate_legacy_review_states(connection)
            _migrate_analysis_run_model_metadata(connection)
    except (OSError, sqlite3.Error, PersistenceError) as error:
        if isinstance(error, PersistenceError):
            raise
        raise PersistenceError(
            f"No se pudo inicializar la base SQLite {database_path}: {error}"
        ) from error
    return Path(database_path)


def create_analysis_run(
    database_path: str | Path,
    *,
    source: str,
    model_reference: str,
    model_id: str | None = None,
    decision_rule: str | None = None,
    decision_threshold: float | None = None,
    model_sha256: str | None = None,
    started_at: str | None = None,
) -> str:
    """Registra una ejecución antes de inferir para conservar también fallos."""

    if not source.strip():
        raise ValueError("source no puede estar vacío.")
    if not model_reference.strip():
        raise ValueError("model_reference no puede estar vacío.")
    if decision_rule not in (None, "predict", "predict_proba_gte"):
        raise ValueError("decision_rule debe ser predict o predict_proba_gte.")
    if decision_threshold is not None and (
        not math.isfinite(float(decision_threshold))
        or not 0.0 <= float(decision_threshold) <= 1.0
    ):
        raise ValueError("decision_threshold debe estar entre 0 y 1.")
    if model_sha256 is not None and (
        len(model_sha256) != 64
        or any(character not in "0123456789abcdef" for character in model_sha256)
    ):
        raise ValueError("model_sha256 debe ser un SHA-256 hexadecimal en minúsculas.")
    if (decision_rule == "predict_proba_gte") != (decision_threshold is not None):
        raise ValueError(
            "predict_proba_gte requiere un umbral; predict debe usar umbral NULL."
        )
    run_id = str(uuid.uuid4())
    timestamp = started_at or _utc_now()
    try:
        with _connect(database_path) as connection:
            connection.execute(
                """
                INSERT INTO analysis_runs
                    (run_id, started_at, source, model_reference, model_id,
                     decision_rule, decision_threshold, model_sha256, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running')
                """,
                (
                    run_id,
                    timestamp,
                    source,
                    model_reference,
                    model_id,
                    decision_rule,
                    decision_threshold,
                    model_sha256,
                ),
            )
    except (sqlite3.Error, PersistenceError) as error:
        if isinstance(error, PersistenceError):
            raise
        raise PersistenceError(f"No se pudo registrar la ejecución: {error}") from error
    return run_id


def complete_analysis_run(
    database_path: str | Path,
    run_id: str,
    *,
    record_ids: Sequence[str],
    predictions: Sequence[int],
    scores: Sequence[float | None],
    finished_at: str | None = None,
) -> int:
    """Completa una ejecución e inserta alertas solo para predicciones clase 1."""

    if not (len(record_ids) == len(predictions) == len(scores)):
        raise ValueError("record_ids, predictions y scores deben tener igual longitud.")
    if any(not isinstance(record_id, str) or not record_id.strip() for record_id in record_ids):
        raise ValueError("Cada record_id debe ser un texto no vacío.")
    if len(set(record_ids)) != len(record_ids):
        raise ValueError("record_ids deben ser únicos dentro de una ejecución.")
    if any(prediction not in (0, 1) for prediction in predictions):
        raise ValueError("Las predicciones deben ser binarias: 0 o 1.")

    alerts: list[tuple[str, str, str, int, float | None]] = []
    for record_id, prediction, score in zip(record_ids, predictions, scores):
        if score is not None:
            numeric_score = float(score)
            if not math.isfinite(numeric_score) or not 0.0 <= numeric_score <= 1.0:
                raise ValueError("Los scores deben ser finitos y estar entre 0 y 1.")
            score = numeric_score
        if prediction == 1:
            alerts.append((run_id, record_id, _utc_now(), 1, score))

    try:
        with _connect(database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE analysis_runs
                SET status = 'completed',
                    finished_at = ?,
                    records_processed = ?,
                    alerts_created = ?,
                    error_message = NULL
                WHERE run_id = ? AND status = 'running'
                """,
                (finished_at or _utc_now(), len(predictions), len(alerts), run_id),
            )
            if cursor.rowcount != 1:
                raise PersistenceError(
                    f"La ejecución {run_id} no existe o no está en estado running."
                )
            connection.executemany(
                """
                INSERT INTO alerts
                    (run_id, record_id, detected_at, predicted_class, model_score)
                VALUES (?, ?, ?, ?, ?)
                """,
                alerts,
            )
    except (sqlite3.Error, PersistenceError) as error:
        if isinstance(error, PersistenceError):
            raise
        raise PersistenceError(
            f"No se pudo completar la ejecución {run_id}: {error}"
        ) from error
    return len(alerts)


def fail_analysis_run(
    database_path: str | Path,
    run_id: str,
    error_message: str,
    *,
    finished_at: str | None = None,
) -> None:
    """Marca fallida una ejecución de inferencia y conserva un mensaje acotado."""

    if not error_message.strip():
        error_message = "Fallo sin mensaje."
    try:
        with _connect(database_path) as connection:
            cursor = connection.execute(
                """
                UPDATE analysis_runs
                SET status = 'failed', finished_at = ?, error_message = ?
                WHERE run_id = ? AND status = 'running'
                """,
                (finished_at or _utc_now(), error_message[:2000], run_id),
            )
            if cursor.rowcount != 1:
                raise PersistenceError(
                    f"La ejecución {run_id} no existe o no está en estado running."
                )
    except (sqlite3.Error, PersistenceError) as error:
        if isinstance(error, PersistenceError):
            raise
        raise PersistenceError(
            f"No se pudo marcar como fallida la ejecución {run_id}: {error}"
        ) from error


def list_analysis_runs(
    database_path: str | Path = DEFAULT_DATABASE_PATH,
    *,
    limit: int = 100,
) -> list[dict[str, object]]:
    """Devuelve las ejecuciones más recientes."""

    if not 1 <= limit <= 10000:
        raise ValueError("limit debe estar entre 1 y 10000.")
    try:
        with _connect(database_path) as connection:
            rows = connection.execute(
                """
                SELECT run_id, started_at, finished_at, source, model_reference,
                       model_id, decision_rule, decision_threshold, model_sha256,
                       status, records_processed, alerts_created, error_message
                FROM analysis_runs
                ORDER BY started_at DESC, run_id
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
    except (sqlite3.Error, PersistenceError) as error:
        if isinstance(error, PersistenceError):
            raise
        raise PersistenceError(f"No se pudieron consultar ejecuciones: {error}") from error
    return [dict(row) for row in rows]


def list_alerts(
    database_path: str | Path = DEFAULT_DATABASE_PATH,
    *,
    run_id: str | None = None,
    review_state: str | None = None,
    limit: int = 100,
) -> list[dict[str, object]]:
    """Consulta alertas y metadata de ejecución sin perder ejecuciones antiguas."""

    if not 1 <= limit <= 10000:
        raise ValueError("limit debe estar entre 1 y 10000.")
    if review_state is not None and review_state not in REVIEW_STATES:
        raise ValueError(f"review_state debe ser uno de {sorted(REVIEW_STATES)}.")

    clauses: list[str] = []
    parameters: list[object] = []
    if run_id is not None:
        clauses.append("a.run_id = ?")
        parameters.append(run_id)
    if review_state is not None:
        clauses.append("a.review_state = ?")
        parameters.append(review_state)
    where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    parameters.append(limit)

    try:
        with _connect(database_path) as connection:
            rows = connection.execute(
                f"""
                SELECT a.alert_id, a.run_id, a.record_id, a.detected_at,
                       a.predicted_class, a.model_score, a.review_state,
                       r.source, r.model_id, r.model_reference, r.decision_rule,
                       r.decision_threshold, r.model_sha256,
                       r.started_at AS run_started_at, r.status AS run_status
                FROM alerts AS a
                LEFT JOIN analysis_runs AS r ON r.run_id = a.run_id
                {where_clause}
                ORDER BY a.detected_at DESC, a.alert_id DESC
                LIMIT ?
                """,
                parameters,
            ).fetchall()
    except (sqlite3.Error, PersistenceError) as error:
        if isinstance(error, PersistenceError):
            raise
        raise PersistenceError(f"No se pudieron consultar alertas: {error}") from error
    return [dict(row) for row in rows]


def update_alert_review_state(
    database_path: str | Path,
    alert_id: int,
    review_state: str,
) -> None:
    """Actualiza el estado de revisión de una alerta existente."""

    if review_state not in REVIEW_STATES:
        raise ValueError(f"review_state debe ser uno de {sorted(REVIEW_STATES)}.")
    try:
        with _connect(database_path) as connection:
            cursor = connection.execute(
                "UPDATE alerts SET review_state = ? WHERE alert_id = ?",
                (review_state, alert_id),
            )
            if cursor.rowcount != 1:
                raise PersistenceError(f"No existe la alerta {alert_id}.")
    except (sqlite3.Error, PersistenceError) as error:
        if isinstance(error, PersistenceError):
            raise
        raise PersistenceError(
            f"No se pudo actualizar la revisión de la alerta {alert_id}: {error}"
        ) from error
