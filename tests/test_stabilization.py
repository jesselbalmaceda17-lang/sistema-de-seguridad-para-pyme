"""Regressions for defects reproduced during functional stabilization."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from seguridad_pymes.dashboard import _read_uploaded_csv
from seguridad_pymes.dashboard import _prediction_report
from seguridad_pymes.database import initialize_database, create_analysis_run, complete_analysis_run
from seguridad_pymes.inference import InferenceRunResult, PRODUCTION_MODEL_ID


class CSVStructureRegressionTests(unittest.TestCase):
    def test_extra_first_row_field_must_not_become_an_implicit_index(self):
        with self.assertRaisesRegex(ValueError, 'campos|columnas|estructura'):
            _read_uploaded_csv(io.BytesIO(b'a,b\n1,2,3\n'))

    def test_numeric_implicit_index_is_not_a_valid_csv_row(self):
        with self.assertRaisesRegex(ValueError, 'campos|columnas|estructura'):
            _read_uploaded_csv(io.BytesIO(b'a,b\n0,2,3\n1,4,5\n'))

    def test_valid_quoted_fields_and_multiline_values_keep_their_columns(self):
        frame, header = _read_uploaded_csv(io.BytesIO(b'a,b\n"first, value","line1\nline2"\n'))
        self.assertEqual(header, ['a', 'b'])
        self.assertEqual(frame.iloc[0].tolist(), ['first, value', 'line1\nline2'])


class CorruptModelRegressionTests(unittest.TestCase):
    def test_corrupt_joblib_frame_is_reported_without_streamlit_exception(self):
        with tempfile.TemporaryDirectory(prefix='sipymes-corrupt-model-') as directory:
            root = Path(directory)
            model = root / 'broken.joblib'
            model.write_bytes(b'\x80\x05\x95\xff\xff\xff\xff\xff\xff\xff\x7f')
            with patch.dict(os.environ, {'SIPYMES_MODEL_PATH': str(model),
                                         'SIPYMES_DATABASE_PATH': str(root / 'isolated.sqlite3')}):
                app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'app.py')).run(timeout=30)
            self.assertEqual(len(app.exception), 0)
            self.assertTrue(any('No se pudo cargar' in e.value for e in app.error))


class DashboardLimitRegressionTests(unittest.TestCase):
    def test_uploader_limit_matches_the_advertised_100_mb(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {'SIPYMES_DATABASE_PATH': str(Path(directory) / 'isolated.sqlite3')}):
                app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'app.py')).run(timeout=30)
            self.assertEqual(app.get('file_uploader')[0].proto.max_upload_size_mb, 100)

    def test_json_report_explicitly_marks_alert_list_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'isolated.sqlite3'
            initialize_database(db)
            run_id = create_analysis_run(db, source='fixture.csv', model_reference='test model')
            count = 10001
            ids = [f'fixture-{i}' for i in range(count)]
            complete_analysis_run(db, run_id, record_ids=ids, predictions=[1]*count, scores=[.7]*count)
            result = InferenceRunResult(run_id, count, count, (1,)*count, (.7,)*count, db,
                model_id=PRODUCTION_MODEL_ID, decision_rule='predict', model_reference='test model')
            app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'app.py'))
            app.session_state['latest_report'] = _prediction_report(result, ids, 'fixture.csv')
            app.session_state['latest_result'] = result
            app.session_state['latest_run'] = {'run_id': run_id, 'source': 'fixture.csv',
                'records_processed': count, 'alerts_created': count, 'model_id': PRODUCTION_MODEL_ID,
                'model_reference': 'test model', 'decision_rule': 'predict', 'decision_threshold': None,
                'model_sha256': None}
            with patch.dict(os.environ, {'SIPYMES_DATABASE_PATH': str(db)}), patch('seguridad_pymes.dashboard.st.download_button') as download:
                app.run(timeout=60)
            self.assertEqual(len(app.exception), 0)
            payload = next(json.loads(call.kwargs['data']) for call in download.call_args_list
                if call.kwargs.get('key') == 'download_current_json')
            self.assertEqual(len(payload['alerts']), 10000)
            self.assertTrue(payload.get('alerts_truncated'))
            self.assertEqual(payload.get('alerts_returned'), 10000)
            self.assertEqual(payload.get('alerts_total'), count)


if __name__ == '__main__':
    unittest.main(verbosity=2)
