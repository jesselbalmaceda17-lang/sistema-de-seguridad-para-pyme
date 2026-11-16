"""Separate live-monitor release; previous CSV distribution stays byte-identical."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
OUT = Path(__file__).resolve().parent
OLD = ROOT / 'dist/SeguridadInteligentePYMES-entrega-20261109'
PACKAGE = ROOT / 'dist/SeguridadInteligentePYMES-monitoreo-20261109'
if not PACKAGE.exists():
    shutil.copytree(OLD, PACKAGE)
modules = ['__init__', 'dashboard', 'database', 'inference', 'resources', 'training', 'ingestion',
           'pcap_reader', 'pcap_extract', 'pcap_schema', 'monitor_process', 'monitor_capture',
           'monitor_flows', 'monitor_rules', 'monitor_store', 'monitoring', 'monitor_ui', 'monitor_demo']
for name in modules:
    shutil.copy2(ROOT / 'seguridad_pymes' / f'{name}.py', PACKAGE / 'seguridad_pymes' / f'{name}.py')
shutil.copy2(ROOT / 'app.py', PACKAGE / 'app.py')
from tests.pcap_fixtures import ethernet_packet, pcap
(PACKAGE / 'demo/laboratorio_sintetico.pcap').write_bytes(pcap([(1000000, ethernet_packet(payload=b'lab')), (2000000, ethernet_packet(reverse=True, payload=b'ok'))]))
for name in ['README.md', 'RECUPERACION.md']:
    shutil.copy2(OUT / f'paquete_{name}', PACKAGE / name)
version = {'release': 'monitoreo-autorizado-20261109', 'platform_verified': 'Windows 11 x64 / Python 3.14.6',
    'requirements_unchanged': True, 'new_python_dependencies': [], 'capture_dependencies': ['TShark 4.6.9', 'Npcap'],
    'csv_model_sha256': '58505ee89df22c4c223b66d5e7172388d5d1fad6b7d135fce800a2765b2029e9',
    'rule_detector': 'transparent_rules_v1', 'pcap_rf_included': False, 'offline_pcap_features_unchanged': 38,
    'csv_features_unchanged': 42, 'another_physical_machine_verified': False}
(PACKAGE / 'VERSIONES.json').write_text(json.dumps(version, indent=2), encoding='utf-8')
proof = OUT / 'paquete_VERIFICACION.md'
if proof.exists():
    shutil.copy2(proof, PACKAGE / 'VERIFICACION.md')
else:
    (PACKAGE / 'VERIFICACION.md').write_text('Verificación de esta versión de monitoreo en curso. La versión anterior CSV se conserva separada.\n', encoding='utf-8')
files = []
for path in sorted(PACKAGE.rglob('*')):
    if path.is_file() and path.name != 'manifest.sha256.json':
        assert '__pycache__' not in path.parts and path.suffix not in {'.sqlite3', '.pyc'}
        with path.open('rb') as handle:
            digest = hashlib.file_digest(handle, 'sha256').hexdigest()
        files.append({'path': path.relative_to(PACKAGE).as_posix(), 'size_bytes': path.stat().st_size, 'sha256': digest})
(PACKAGE / 'manifest.sha256.json').write_text(json.dumps({'manifest_version': 1,
    'generated_at_utc': datetime.now(timezone.utc).isoformat(), 'hash_algorithm': 'SHA-256',
    'self_excluded': 'manifest.sha256.json', 'files': files,
    'trust_notice': 'Load only trusted serialized models; hashes establish integrity, not publisher identity.'}, indent=2), encoding='utf-8')
print(json.dumps({'package': str(PACKAGE), 'files_including_manifest': len(files) + 1}))
