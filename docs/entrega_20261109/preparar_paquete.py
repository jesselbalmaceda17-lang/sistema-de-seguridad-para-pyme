"""Stage a minimal runtime package without editing development files."""
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
PACKAGE = ROOT / 'dist/SeguridadInteligentePYMES-entrega-20261109'
assert (OUT / 'respaldo_inicial.json').is_file(), 'Verified backup required first'
PACKAGE.mkdir(parents=True, exist_ok=False)
operational = ['app.py', 'requirements.txt', 'requirements-lock.txt']
operational += ['seguridad_pymes/' + name + '.py' for name in ['__init__', 'dashboard', 'database', 'inference', 'resources', 'training', 'ingestion']]
operational += ['models/unsw_nb15_random_forest.joblib', 'models/unsw_nb15_random_forest.joblib.metadata.json']
inventory = []
for rel in operational:
    source, target = ROOT / rel, PACKAGE / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    with source.open('rb') as handle:
        digest = hashlib.file_digest(handle, 'sha256').hexdigest()
    assert hashlib.sha256(target.read_bytes()).hexdigest() == digest
    inventory.append({'path': rel, 'source_identical': True, 'sha256': digest})
(PACKAGE / 'demo').mkdir()
shutil.copy2(ROOT / 'docs/estabilizacion_20261109/fixtures/valido.csv', PACKAGE / 'demo/demostracion_sintetica.csv')
old = json.loads((ROOT / 'docs/estabilizacion_20261109/oraculo_modelo.json').read_text(encoding='utf-8'))
oracle = {key: old[key] for key in ['model_sha256', 'ids', 'predictions', 'scores']}
oracle['notice'] = 'Synthetic software consistency fixture; predictions are not ground-truth labels or evidence of detector accuracy.'
(PACKAGE / 'demo/resultados_esperados.json').write_text(json.dumps(oracle, indent=2, ensure_ascii=False), encoding='utf-8')
(PACKAGE / '.streamlit').mkdir()
(PACKAGE / '.streamlit/config.toml').write_text('[server]\naddress = "127.0.0.1"\nport = 8501\nheadless = true\nmaxUploadSize = 100\n\n[browser]\ngatherUsageStats = false\n', encoding='utf-8')
(OUT / 'seleccion_archivos.json').write_text(json.dumps({'package': PACKAGE.relative_to(ROOT).as_posix(), 'operational_copies': inventory,
    'excluded': ['research datasets and captures', 'all PCAP models', 'optional CSV threshold-study model', 'original SQLite databases', 'historical backups', 'tests and evidence', '.venv and caches'],
    'training_and_ingestion_reason': 'Imported by the existing trusted model loader; files retained byte-identical to avoid refactoring. No training data shipped and no training command invoked.'}, indent=2), encoding='utf-8')
print(json.dumps({'package': str(PACKAGE), 'operational_copies': len(inventory)}))
