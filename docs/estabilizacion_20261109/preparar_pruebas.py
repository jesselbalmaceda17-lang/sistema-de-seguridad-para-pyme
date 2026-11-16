"""Controlled synthetic CSV fixtures and direct stored-model oracles; no fitting."""
from pathlib import Path
import hashlib
import importlib.metadata
import json
import platform
import sys
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from seguridad_pymes.training import load_trained_model, DEFAULT_MODEL_PATH
from seguridad_pymes.inference import _model_input_schema

fixtures = OUT / 'fixtures'
fixtures.mkdir(exist_ok=False)
model = load_trained_model(DEFAULT_MODEL_PATH)
features, numeric = _model_input_schema(model)
rows = []
for scale in [0, 1, 2, 5, 10, 100, 1000, 10000]:
    for proto, service, state in [('tcp', 'http', 'FIN'), ('udp', 'dns', 'INT'), ('tcp', '-', 'CON')]:
        row = {name: scale for name in numeric}
        row.update(proto=proto, service=service, state=state)
        rows.append(row)
samples = pd.DataFrame(rows).loc[:, features]
predictions = model.predict(samples)
chosen = [i for label in (0, 1) for i in np.flatnonzero(predictions == label)[:4]]
assert set(predictions[chosen]) == {0, 1}, 'Controlled examples need both predicted classes'
frame = samples.iloc[chosen].copy().reset_index(drop=True)
frame.insert(0, 'id', [f'controlled-{i+1}' for i in range(len(frame))])
frame.to_csv(fixtures / 'valido.csv', index=False)
(fixtures / 'vacio.csv').write_bytes(b'')
(fixtures / 'solo_encabezado.csv').write_text(','.join(frame.columns) + '\n', encoding='utf-8')
frame.drop(columns=[features[0]]).to_csv(fixtures / 'columna_faltante.csv', index=False)
bad = frame.copy()
bad[numeric[0]] = bad[numeric[0]].astype('object')
bad.loc[0, numeric[0]] = 'not-a-number'
bad.to_csv(fixtures / 'numero_invalido.csv', index=False)
for name, value in [('no_finito.csv', 'inf'), ('faltante.csv', '')]:
    invalid = bad.copy()
    invalid.loc[0, numeric[0]] = value
    invalid.to_csv(fixtures / name, index=False)
duplicate = frame.copy()
duplicate.loc[1, 'id'] = duplicate.loc[0, 'id']
duplicate.to_csv(fixtures / 'id_duplicado.csv', index=False)
text = frame.to_csv(index=False)
(fixtures / 'campo_extra.csv').write_text(text.splitlines()[0] + '\n' + '\n'.join(line + ',EXTRA' for line in text.splitlines()[1:]) + '\n', encoding='utf-8')
(fixtures / 'codificacion_invalida.csv').write_bytes(b'\xff\xfe\x00')
oracle = {'source': 'Controlled synthetic inputs; predicted classes are an oracle for software consistency, not ground truth',
          'model_path': str(DEFAULT_MODEL_PATH), 'model_sha256': hashlib.sha256(DEFAULT_MODEL_PATH.read_bytes()).hexdigest(),
          'features': list(features), 'numeric': list(numeric), 'ids': frame['id'].tolist(),
          'predictions': [int(x) for x in model.predict(frame.loc[:, features])],
          'scores': model.predict_proba(frame.loc[:, features])[:, list(model.classes_).index(1)].tolist(),
          'fixture_sha256': hashlib.sha256((fixtures / 'valido.csv').read_bytes()).hexdigest(),
          'python': sys.version, 'platform': platform.platform(),
          'direct_dependencies': {name: importlib.metadata.version(name) for name in ['pandas', 'numpy', 'scikit-learn', 'streamlit', 'joblib', 'psutil']}}
(OUT / 'oraculo_modelo.json').write_text(json.dumps(oracle, indent=2), encoding='utf-8')
print(json.dumps(oracle, indent=2))
