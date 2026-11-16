"""Functional acceptance of stored models, Streamlit, SQLite and offline fixtures."""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import traceback
from unittest.mock import patch

import numpy as np
import pandas as pd
import psutil
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from seguridad_pymes.dashboard import _read_uploaded_csv, _prepare_uploaded_records
from seguridad_pymes.database import initialize_database, list_analysis_runs, list_alerts, update_alert_review_state, PersistenceError
from seguridad_pymes.inference import run_model_analysis, _model_input_schema, model_configuration, THRESHOLD_STUDY_MODEL_ID
from seguridad_pymes.training import load_trained_model
from seguridad_pymes.pcap_extract import extract_capture
from seguridad_pymes.pcap_reader import CaptureError
from tests.pcap_fixtures import ethernet_packet, pcap, pcapng

RUN = OUT / (sys.argv[1] if len(sys.argv) > 1 else 'integral_run_001')
RUN.mkdir(exist_ok=False)
oracle = json.loads((OUT / 'oraculo_modelo.json').read_text(encoding='utf-8'))
fixture = OUT / 'fixtures/valido.csv'
results = []


def record(name, function):
    start = time.perf_counter()
    try:
        details = function()
        results.append({'case': name, 'passed': True, 'wall_seconds': time.perf_counter()-start, 'details': details})
        print('PASS', name, flush=True)
    except Exception as error:
        results.append({'case': name, 'passed': False, 'wall_seconds': time.perf_counter()-start,
                        'error': str(error), 'traceback': traceback.format_exc()})
        print('FAIL', name, str(error), flush=True)


class Uploaded(io.BytesIO):
    def __init__(self, path):
        super().__init__(path.read_bytes())
        self.name = path.name


def ui_csv(name, valid=False, execute=True):
    path = OUT / 'fixtures' / name
    db = RUN / (path.stem + '.sqlite3')
    with patch.dict(os.environ, {'SIPYMES_DATABASE_PATH': str(db)}), patch('seguridad_pymes.dashboard.st.file_uploader', return_value=Uploaded(path)), patch('seguridad_pymes.dashboard.st.download_button') as downloads:
        os.environ.pop('SIPYMES_MODEL_PATH', None)
        app = AppTest.from_file(str(ROOT / 'app.py')).run(timeout=60)
        buttons = [b for b in app.button if b.label == 'Ejecutar análisis del archivo']
        if execute and buttons:
            buttons[0].click().run(timeout=60)
        assert not app.exception, str(app.exception)
        runs = list_analysis_runs(db)
        if valid:
            assert len(runs) == 1 and runs[0]['status'] == 'completed'
            result = app.session_state['latest_result']
            assert list(result.predictions) == oracle['predictions']
            assert list(result.attack_scores) == oracle['scores']
            assert result.records_processed == 8 and result.alerts_created == 4
            assert {x.label: x.value for x in app.metric} == {'Registros analizados': '8', 'Normales': '4', 'Sospechosos': '4', 'Alertas guardadas': '4'}
            alerts = sorted(list_alerts(db), key=lambda x: x['record_id'])
            assert [a['record_id'] for a in alerts] == oracle['ids'][4:]
            payload = next(json.loads(c.kwargs['data']) for c in downloads.call_args_list if c.kwargs.get('key') == 'download_current_json')
            assert len(payload['records']) == 8 and len(payload['alerts']) == 4
            assert payload['alerts_truncated'] is False and payload['alerts_returned'] == payload['alerts_total'] == 4
            csv_bytes = next(c.kwargs['data'] for c in downloads.call_args_list if c.kwargs.get('key') == 'download_current_csv')
            exported = pd.read_csv(io.BytesIO(csv_bytes))
            assert exported['identificador_registro'].tolist() == oracle['ids']
            np.testing.assert_allclose(exported['Score del modelo (clase 1)'], oracle['scores'], rtol=0, atol=1e-15)
            displayed = app.dataframe[0].value
            assert displayed['identificador_registro'].tolist() == oracle['ids']
            assert displayed['clasificacion_predicha'].tolist() == ['Normal']*4 + ['Sospechoso (ataque)']*4
            (RUN/'ui_exportacion.json').write_text(json.dumps(payload, indent=2), encoding='utf-8')
            (RUN/'ui_exportacion.csv').write_bytes(csv_bytes)
            return {'records': 8, 'alerts': 4, 'display_and_exports_match_model_and_sqlite': True}
        assert not runs, 'Invalid input must not create a run'
        assert app.error, 'Invalid input must be explained'
        return {'errors': [e.value for e in app.error], 'runs_created': 0}


record('Streamlit_CSV_original_model_alerts_SQLite_display_exports', lambda: ui_csv('valido.csv', valid=True))
for name in ['vacio.csv', 'solo_encabezado.csv', 'columna_faltante.csv', 'numero_invalido.csv',
             'no_finito.csv', 'faltante.csv', 'id_duplicado.csv', 'codificacion_invalida.csv', 'campo_extra.csv']:
    record('Streamlit_reject_' + name, lambda name=name: ui_csv(name))


def replay_and_sql():
    frame, headers = _read_uploaded_csv(Uploaded(fixture))
    records, ids, _ = _prepare_uploaded_records(frame, headers, tuple(oracle['features']), fixture.name)
    db = RUN / 'replay.sqlite3'
    source = "fixture'; DROP TABLE alerts; --.csv"
    first = run_model_analysis(records, ids, source=source, database_path=db)
    second = run_model_analysis(records, ids, source=source, database_path=db)
    assert first.predictions == second.predictions == tuple(oracle['predictions'])
    assert first.attack_scores == second.attack_scores == tuple(oracle['scores'])
    assert len(list_alerts(db, run_id="' OR 1=1 --")) == 0
    alerts = list_alerts(db, run_id=first.run_id)
    update_alert_review_state(db, alerts[0]['alert_id'], 'false_positive')
    with closing(sqlite3.connect(db)) as conn:
        assert conn.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
        assert conn.execute('SELECT count(*) FROM alerts').fetchone()[0] == 8
    assert list_alerts(db, run_id=first.run_id, review_state='false_positive')[0]['predicted_class'] == 1
    return {'replays': 2, 'same_predictions_and_scores': True, 'runs': 2, 'alerts': 8,
            'literal_sql_source': source, 'manual_review_preserves_prediction': True}


record('Replay_SQL_parameterization_manual_review_independent_connection', replay_and_sql)


def threshold_policy():
    config = model_configuration(THRESHOLD_STUDY_MODEL_ID)
    model = load_trained_model(config.model_path)
    frame, headers = _read_uploaded_csv(Uploaded(fixture))
    expected, numeric = _model_input_schema(model)
    records, ids, _ = _prepare_uploaded_records(frame, headers, expected, fixture.name)
    from seguridad_pymes.inference import _validate_records
    scores = model.predict_proba(_validate_records(records, expected, numeric))[:, list(model.classes_).index(1)]
    result = run_model_analysis(records, ids, source=fixture.name, model_path=config.model_path,
        model_id=config.model_id, database_path=RUN/'threshold.sqlite3')
    assert result.decision_threshold == .65
    assert list(result.predictions) == (scores >= .65).astype(int).tolist()
    return {'rule': result.decision_rule, 'threshold_unchanged': result.decision_threshold,
            'model_is_csv_threshold_study_not_pcap': True, 'predictions': result.predictions}


record('Existing_CSV_threshold_selector_policy_unchanged', threshold_policy)


def app_error(name, model=None, database=None):
    env = {'SIPYMES_DATABASE_PATH': str(database or RUN/(name+'.sqlite3'))}
    if model is not None:
        env['SIPYMES_MODEL_PATH'] = str(model)
    with patch.dict(os.environ, env):
        if model is None:
            os.environ.pop('SIPYMES_MODEL_PATH', None)
        app = AppTest.from_file(str(ROOT/'app.py')).run(timeout=60)
    assert not app.exception and app.error
    return {'errors': [e.value for e in app.error], 'unhandled_exceptions': 0}


record('Missing_model_actionable_UI_error', lambda: app_error('missing_model', model=RUN/'absent.joblib'))
record('Model_path_is_a_directory_UI_error', lambda: app_error('directory_model', model=RUN))
record('PCAP_experiment_model_cannot_enter_CSV_detection', lambda: app_error('pcap_model', model=ROOT/'experiments/pcap_v1/run_003/held_out_torii/random_forest.joblib'))
bad_db = RUN/'corrupt.sqlite3'
bad_db.write_bytes(b'not a SQLite database')
record('Corrupt_SQLite_safe_UI_error', lambda: app_error('corrupt_sqlite', database=bad_db))
blocked = RUN/'not_a_directory'
blocked.write_text('controlled file')
record('Invalid_database_parent_safe_UI_error', lambda: app_error('invalid_parent', database=blocked/'history.sqlite3'))


def oversize():
    try:
        _read_uploaded_csv(io.BytesIO(b'x' * (100*1024**2+1)))
    except ValueError as error:
        assert '100 MB' in str(error)
        return {'bytes': 100*1024**2+1, 'rejected_before_csv_parse': True}
    raise AssertionError('Oversize accepted')


record('Upload_above_actual_100_MiB_guard', oversize)


def offline():
    packets = [(1000000, ethernet_packet(payload=b'abc')), (2000000, ethernet_packet(reverse=True, payload=b'xy'))]
    path = RUN/'controlled.pcap'
    path.write_bytes(pcap(packets))
    alternate = RUN/'controlled.pcapng'
    alternate.write_bytes(pcapng(packets))
    first, second, ng = extract_capture(path), extract_capture(path), extract_capture(alternate)
    assert first == second
    assert first['quality']['packets_seen'] == first['quality']['packets_accepted'] == 2
    assert len(first['flows']) == 1 and len(first['feature_definitions']) == 38
    features = first['flows'][0]['features']
    assert features == ng['flows'][0]['features']
    assert features['forward_packet_count']['value'] == features['reverse_packet_count']['value'] == 1
    assert features['forward_ipv4_byte_count']['value'] == 31
    assert features['reverse_ipv4_byte_count']['value'] == 30
    for suffix in ['pcap', 'pcapng']:
        command = [sys.executable, '-B', '-m', 'seguridad_pymes.pcap_extract', str(RUN/('controlled.'+suffix)), '--output', str(RUN/(suffix+'.json'))]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=130)
        assert result.returncode == 0, result.stderr
    for invalid in [RUN/'absent.pcap', RUN/'truncated.pcap']:
        if invalid.name.startswith('truncated'):
            invalid.write_bytes(path.read_bytes()[:-1])
        try:
            extract_capture(invalid)
        except CaptureError:
            pass
        else:
            raise AssertionError('Invalid PCAP accepted')
    try:
        extract_capture(path, tshark_path=RUN/'missing_tshark.exe')
    except CaptureError as error:
        dependency_error = str(error)
    else:
        raise AssertionError('Missing TShark accepted')
    return {'classic_and_ng_CLI': True, 'byte_reproducible_replay': True, 'features': 38,
            'packets': 2, 'flows': 1, 'independent_byte_count_oracle': True,
            'missing_dependency_error': dependency_error, 'classification_or_capture_executed': False}


record('Offline_PCAP_PCAPNG_CLI_replay_and_invalid_paths_dependency', offline)


def batch():
    frame, headers = _read_uploaded_csv(Uploaded(fixture))
    records, _, _ = _prepare_uploaded_records(frame, headers, tuple(oracle['features']), fixture.name)
    large = pd.concat([records]*1250, ignore_index=True)
    start = time.perf_counter()
    result = run_model_analysis(large, [f'batch-{i}' for i in range(len(large))],
        source='controlled_10000.csv', database_path=RUN/'batch.sqlite3')
    assert list(result.predictions) == oracle['predictions']*1250
    assert result.alerts_created == 5000 and len(list_alerts(RUN/'batch.sqlite3', limit=10000)) == 5000
    return {'records': 10000, 'alerts': 5000, 'wall_including_validation_and_sqlite_seconds': time.perf_counter()-start,
            'inference_resources': result.resource_measurement.__dict__, 'scope': 'Synthetic software load test; not detector accuracy or benchmark'}


record('Controlled_10000_row_load_and_complete_alert_persistence', batch)
report = {'finished_at_utc': datetime.now(timezone.utc).isoformat(), 'cases': results,
          'passed': sum(r['passed'] for r in results), 'failed': sum(not r['passed'] for r in results),
          'all_passed': all(r['passed'] for r in results),
          'peak_process_working_set_bytes': getattr(psutil.Process().memory_info(), 'peak_wset', None),
          'scope': 'AppTest uses real render, original models and isolated SQLite; only upload transport/download widgets intercepted. Browser path separately tested without mocks. No fitting.'}
(RUN/'resultados.json').write_text(json.dumps(report, indent=2, default=str), encoding='utf-8')
print(json.dumps({k:v for k,v in report.items() if k != 'cases'}, indent=2))
raise SystemExit(0 if report['all_passed'] else 1)
