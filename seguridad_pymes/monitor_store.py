"""Separate SQLite history for observed traffic and rule alerts, never RF alerts."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

import psutil
from seguridad_pymes.database import PersistenceError, REVIEW_STATES

SCHEMA = '''
CREATE TABLE IF NOT EXISTS monitoring_sessions (
 session_id TEXT PRIMARY KEY, owner_pid INTEGER NOT NULL, owner_created REAL NOT NULL,
 started_at TEXT NOT NULL, ended_at TEXT, interface_id TEXT NOT NULL, interface_name TEXT NOT NULL,
 source_kind TEXT NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '',
 config_json TEXT NOT NULL, counters_json TEXT NOT NULL, capture_path TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS monitoring_flows (
 flow_id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES monitoring_sessions(session_id),
 connection_id TEXT NOT NULL, flow_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS monitoring_alerts (
 event_id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES monitoring_sessions(session_id),
 detector TEXT NOT NULL CHECK(detector = 'transparent_rules_v1'), rule TEXT NOT NULL,
 source TEXT NOT NULL, severity TEXT NOT NULL CHECK(severity IN ('baja','media')),
 detected_at TEXT NOT NULL, message TEXT NOT NULL, evidence_json TEXT NOT NULL,
 review_state TEXT NOT NULL DEFAULT 'pending' CHECK(review_state IN ('pending','confirmed','false_positive'))
);
CREATE INDEX IF NOT EXISTS monitoring_alert_time ON monitoring_alerts(detected_at DESC);
CREATE INDEX IF NOT EXISTS monitoring_flow_session ON monitoring_flows(session_id);
'''


def storage_bytes(directory):
    return sum(path.stat().st_size for path in Path(directory).rglob('*') if path.is_file())


class MonitorStore:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.path = self.root / 'history.sqlite3'

    @contextmanager
    def connect(self, *, read=False):
        connection = None
        try:
            if read:
                connection = sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True, timeout=2)
            else:
                self.root.mkdir(parents=True, exist_ok=True)
                connection = sqlite3.connect(self.path, timeout=2)
            connection.row_factory = sqlite3.Row
            connection.execute('PRAGMA foreign_keys=ON')
            yield connection
            if not read:
                connection.commit()
        except (sqlite3.Error, OSError) as error:
            if connection is not None and not read:
                connection.rollback()
            raise PersistenceError(f'No se pudo acceder al historial de monitoreo: {error}') from error
        finally:
            if connection is not None:
                connection.close()

    def initialize(self):
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            rows = conn.execute("SELECT session_id,owner_pid,owner_created FROM monitoring_sessions WHERE status IN ('starting','capturing','stopping')").fetchall()
            for row in rows:
                try:
                    alive = abs(psutil.Process(row['owner_pid']).create_time() - row['owner_created']) < .01
                except psutil.Error:
                    alive = False
                if not alive:
                    conn.execute("UPDATE monitoring_sessions SET status='interrupted',ended_at=?,reason=? WHERE session_id=?",
                        (datetime.now(timezone.utc).isoformat(), 'El proceso anterior terminó; la captura puede ser parcial.', row['session_id']))

    def create(self, session, interface, config, capture_path, kind='live'):
        owner = psutil.Process()
        with self.connect() as conn:
            conn.execute('INSERT INTO monitoring_sessions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (session, owner.pid, owner.create_time(), datetime.now(timezone.utc).isoformat(), None,
                 interface.identifier, interface.description, kind, 'starting', '', json.dumps(config), '{}', str(capture_path)))

    def persist(self, session, flows, alerts, counters, *, status='capturing', reason='', quota_bytes=None):
        if quota_bytes is not None:
            estimate = 2 * sum(len(json.dumps(flow)) + 512 for flow in flows) + 2 * sum(len(json.dumps(alert)) + 512 for alert in alerts) + 65536
            if storage_bytes(self.root) + estimate > quota_bytes - 1024**2:
                raise PersistenceError('Presupuesto de almacenamiento alcanzado; no se ocultan registros no persistidos.')
        final = status in {'stopped', 'completed', 'failed', 'interrupted'}
        with self.connect() as conn:
            for flow in flows:
                conn.execute('INSERT INTO monitoring_flows VALUES(?,?,?,?) ON CONFLICT(flow_id) DO NOTHING',
                    (flow['flow_id'], session, flow['connection_id'], json.dumps(flow, allow_nan=False)))
            for alert in alerts:
                conn.execute('INSERT INTO monitoring_alerts VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(event_id) DO NOTHING',
                    (alert['event_id'], session, alert['detector'], alert['rule'], alert['source'], alert['severity'],
                     alert['detected_at'], alert['message'], json.dumps(alert, allow_nan=False), 'pending'))
            conn.execute('UPDATE monitoring_sessions SET counters_json=?,status=?,reason=?,ended_at=? WHERE session_id=?',
                (json.dumps(counters), status, reason[:3000], datetime.now(timezone.utc).isoformat() if final else None, session))

    def sessions(self, limit=20):
        if not self.path.exists():
            return []
        with self.connect(read=True) as conn:
            return [dict(row) for row in conn.execute('SELECT * FROM monitoring_sessions ORDER BY started_at DESC LIMIT ?', (limit,))]

    def alerts(self, limit=100):
        if not self.path.exists():
            return []
        with self.connect(read=True) as conn:
            return [dict(row) for row in conn.execute('SELECT * FROM monitoring_alerts ORDER BY detected_at DESC,event_id LIMIT ?', (limit,))]

    def review(self, event_id, state):
        if state not in REVIEW_STATES:
            raise ValueError('Estado de revisión inválido.')
        with self.connect() as conn:
            if conn.execute('UPDATE monitoring_alerts SET review_state=? WHERE event_id=?', (state, event_id)).rowcount != 1:
                raise ValueError('No se encontró la alerta de monitoreo.')
