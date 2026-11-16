"""Acceptance/regressions against the staged package using a clean interpreter."""
import argparse
from contextlib import closing
import hashlib
import importlib
import io
import json
import math
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

parser = argparse.ArgumentParser()
parser.add_argument('package', type=Path)
parser.add_argument('output', type=Path)
args = parser.parse_args()
PACKAGE, OUT = args.package.resolve(), args.output.resolve()
OUT.mkdir(parents=True, exist_ok=False)
os.chdir(PACKAGE)
sys.path.insert(0, str(PACKAGE))
import pandas as pd
from streamlit.testing.v1 import AppTest
from seguridad_pymes.dashboard import _read_uploaded_csv, _prepare_uploaded_records
from seguridad_pymes.inference import run_model_analysis
from seguridad_pymes.database import list_analysis_runs, list_alerts, update_alert_review_state
from seguridad_pymes.training import load_trained_model

ORACLE = json.loads((PACKAGE / 'demo/resultados_esperados.json').read_text(encoding='utf-8'))
FIXTURE = PACKAGE / 'demo/demostracion_sintetica.csv'


class Uploaded(io.BytesIO):
    name = 'demostracion_sintetica.csv'


def records():
    frame, headers = _read_uploaded_csv(io.BytesIO(FIXTURE.read_bytes()))
    return _prepare_uploaded_records(frame, headers, [name for name in headers if name != 'id'], FIXTURE.name)[:2]


def check_result(test, result):
    test.assertEqual(list(result.predictions), ORACLE['predictions'])
    test.assertEqual(result.records_processed, 8)
    test.assertEqual(result.alerts_created, 4)
    test.assertTrue(all(math.isclose(score, ORACLE['scores'][index], rel_tol=0, abs_tol=1e-15)
                        for index, score in enumerate(result.attack_scores)))
    test.assertEqual(result.model_sha256, ORACLE['model_sha256'])


class PackageAcceptance(unittest.TestCase):
    def test_01_imports_and_dependencies_are_isolated(self):
        import importlib.metadata
        import site
        lock = (PACKAGE / 'requirements-lock.txt').read_text(encoding='utf-8')
        versions = []
        for line in lock.splitlines():
            if '==' not in line or line.lstrip().startswith('#'):
                continue
            name, expected = line.strip().split('==')
            actual = importlib.metadata.version(name)
            self.assertEqual(actual, expected)
            versions.append({'name': name, 'expected': expected, 'installed': actual})
        paths = {}
        for name in ['dashboard', 'database', 'inference', 'resources', 'training', 'ingestion']:
            module = importlib.import_module('seguridad_pymes.' + name)
            self.assertTrue(Path(module.__file__).resolve().is_relative_to(PACKAGE))
            paths[name] = str(Path(module.__file__).relative_to(PACKAGE))
        for module in ['streamlit', 'sklearn', 'numpy', 'pandas', 'joblib', 'psutil']:
            loaded = importlib.import_module(module)
            self.assertTrue(Path(loaded.__file__).resolve().is_relative_to(Path(sys.prefix)))
        pip = subprocess.run([sys.executable, '-I', '-m', 'pip', 'check'], capture_output=True, text=True)
        self.assertEqual(pip.returncode, 0, pip.stdout + pip.stderr)
        state = {'versions': versions, 'all_41_versions_match': len(versions) == 41,
                 'pip_check': pip.stdout.strip(), 'python': sys.version, 'prefix': sys.prefix,
                 'base_prefix': sys.base_prefix, 'user_site_enabled': site.ENABLE_USER_SITE,
                 'isolated_flag': sys.flags.isolated, 'sys_path': sys.path, 'package_modules': paths,
                 'pyvenv_cfg': (Path(sys.prefix) / 'pyvenv.cfg').read_text(encoding='utf-8')}
        self.assertFalse(site.ENABLE_USER_SITE)
        self.assertEqual(sys.flags.isolated, 1)
        self.assertIn('include-system-site-packages = false', state['pyvenv_cfg'])
        (OUT / 'instalacion_limpia.json').write_text(json.dumps(state, indent=2), encoding='utf-8')

    def test_02_model_and_repeated_api_predictions(self):
        model = load_trained_model()
        self.assertEqual(len(model.named_steps['preprocessing'].feature_names_in_), 42)
        data, ids = records()
        db = OUT / 'api.sqlite3'
        first = run_model_analysis(data, ids, source=FIXTURE.name, database_path=db)
        second = run_model_analysis(data, ids, source=FIXTURE.name, database_path=db)
        check_result(self, first)
        check_result(self, second)
        self.assertEqual(len(list_analysis_runs(db)), 2)
        self.assertEqual(len(list_alerts(db)), 8)
        alert = list_alerts(db, run_id=first.run_id)[0]
        update_alert_review_state(db, alert['alert_id'], 'false_positive')
        with closing(sqlite3.connect(db)) as connection:
            state = connection.execute('SELECT predicted_class, review_state FROM alerts WHERE alert_id=?', (alert['alert_id'],)).fetchone()
            self.assertEqual(state, (1, 'false_positive'))
            self.assertEqual(connection.execute('PRAGMA integrity_check').fetchone()[0], 'ok')

    def test_03_ui_csv_alerts_and_exports(self):
        db = OUT / 'ui.sqlite3'
        env = {'SIPYMES_DATABASE_PATH': str(db), 'SIPYMES_MODEL_PATH': 'models/unsw_nb15_random_forest.joblib'}
        with patch.dict(os.environ, env), patch('seguridad_pymes.dashboard.st.file_uploader', return_value=Uploaded(FIXTURE.read_bytes())), \
             patch('seguridad_pymes.dashboard.st.download_button') as downloads:
            app = AppTest.from_file(str(PACKAGE / 'app.py')).run(timeout=45)
            next(button for button in app.button if button.label.startswith('Ejecutar')).click().run(timeout=45)
            self.assertFalse(app.exception)
            self.assertFalse(app.error)
            check_result(self, app.session_state['latest_result'])
            self.assertEqual({item.label: item.value for item in app.metric},
                             {'Registros analizados': '8', 'Normales': '4', 'Sospechosos': '4', 'Alertas guardadas': '4'})
            payload = next(json.loads(call.kwargs['data']) for call in downloads.call_args_list if call.kwargs.get('key') == 'download_current_json')
            self.assertEqual(len(payload['records']), 8)
            self.assertEqual(len(payload['alerts']), 4)
            self.assertFalse(payload['alerts_truncated'])
            export = next(call.kwargs['data'] for call in downloads.call_args_list if call.kwargs.get('key') == 'download_current_csv')
            self.assertEqual(pd.read_csv(io.BytesIO(export))['identificador_registro'].tolist(), ORACLE['ids'])
            (OUT / 'ui_reporte.json').write_text(json.dumps(payload, indent=2), encoding='utf-8')
            (OUT / 'ui_predicciones.csv').write_bytes(export)

    def test_04_invalid_csv_no_completed_analysis(self):
        for index, content in enumerate([b'', b'a,b\n1,2,3\n', b'a,b\n1,2\n']):
            db = OUT / f'invalid_{index}.sqlite3'
            with self.subTest(case=index), patch.dict(os.environ, {'SIPYMES_DATABASE_PATH': str(db), 'SIPYMES_MODEL_PATH': 'models/unsw_nb15_random_forest.joblib'}), \
                 patch('seguridad_pymes.dashboard.st.file_uploader', return_value=Uploaded(content)):
                app = AppTest.from_file(str(PACKAGE / 'app.py')).run(timeout=45)
                self.assertFalse(app.exception)
                self.assertTrue(app.error)
                self.assertEqual(list_analysis_runs(db), [])

    def test_05_backup_restore_manual_review_and_refuse_overwrite(self):
        data, ids = records()
        source = OUT / 'recover_source.sqlite3'
        result = run_model_analysis(data, ids, source=FIXTURE.name, database_path=source)
        alert = list_alerts(source)[0]
        update_alert_review_state(source, alert['alert_id'], 'confirmed')
        tool = PACKAGE / 'herramientas/sqlite_respaldo.py'
        backed, restored = OUT / 'recover_backup.sqlite3', OUT / 'recover_restored.sqlite3'
        details = []
        for verb, src, dst in [('backup', source, backed), ('restore', backed, restored)]:
            completed = subprocess.run([sys.executable, '-I', '-B', str(tool), verb, str(src), str(dst)], capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            details.append(json.loads(completed.stdout))
        self.assertEqual(list_analysis_runs(source), list_analysis_runs(restored))
        self.assertEqual(list_alerts(source), list_alerts(restored))
        before = hashlib.sha256(restored.read_bytes()).hexdigest()
        overwrite = subprocess.run([sys.executable, '-I', '-B', str(tool), 'restore', str(backed), str(restored)], capture_output=True, text=True)
        self.assertEqual(overwrite.returncode, 2)
        self.assertEqual(hashlib.sha256(restored.read_bytes()).hexdigest(), before)
        (OUT / 'recuperacion_verificada.json').write_text(json.dumps({'copies': details, 'same_runs_alerts_and_reviews': True, 'existing_destination_refused': True}, indent=2), encoding='utf-8')

    def test_06_corrupt_backup_refused_before_target_creation(self):
        source, target = OUT / 'corrupt.sqlite3', OUT / 'must_not_exist.sqlite3'
        source.write_bytes(b'not a database')
        run = subprocess.run([sys.executable, '-I', '-B', str(PACKAGE / 'herramientas/sqlite_respaldo.py'), 'restore', str(source), str(target)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        self.assertFalse(target.exists())

    def test_07_manifest_and_tampered_file_detection(self):
        tool = PACKAGE / 'herramientas/verificar_paquete.py'
        good = subprocess.run([sys.executable, '-I', '-B', str(tool)], capture_output=True, text=True)
        self.assertEqual(good.returncode, 0, good.stderr)
        modified = OUT / 'tampered_package'
        modified.mkdir()
        (modified / 'herramientas').mkdir()
        shutil.copy2(tool, modified / 'herramientas/verificar_paquete.py')
        (modified / 'sample.txt').write_text('changed', encoding='utf-8')
        (modified / 'manifest.sha256.json').write_text(json.dumps({'files': [{'path': 'sample.txt', 'size_bytes': 8, 'sha256': '0' * 64}]}), encoding='utf-8')
        bad = subprocess.run([sys.executable, '-I', '-B', str(modified / 'herramientas/verificar_paquete.py')], capture_output=True, text=True)
        self.assertEqual(bad.returncode, 2)


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PackageAcceptance))
    (OUT / 'resultados.json').write_text(json.dumps({'tests_run': result.testsRun, 'successful': result.wasSuccessful(),
        'failures': len(result.failures), 'errors': len(result.errors), 'package': str(PACKAGE),
        'python': sys.executable, 'scope': 'Real stored original model, isolated SQLite and AppTest; upload/download transport patched only.'}, indent=2), encoding='utf-8')
    raise SystemExit(0 if result.wasSuccessful() else 2)
