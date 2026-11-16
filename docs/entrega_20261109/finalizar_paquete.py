"""Generate the package's version record and SHA-256 inventory."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
PACKAGE = ROOT / 'dist/SeguridadInteligentePYMES-entrega-20261109'


def read_optional(name):
    path = OUT / name
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else None


installation = read_optional('pruebas_paquete_001/instalacion_limpia.json')
acceptance = read_optional('pruebas_paquete_001/resultados.json')
performance = read_optional('rendimiento_003/resultados.json')
browser = read_optional('navegador_final.json')
versions = {'delivery_id': 'entrega-tecnica-20261109', 'target_os': 'Windows 11 x64',
    'observed_os': platform.platform(), 'python_verified': platform.python_version(),
    'model_sha256': '58505ee89df22c4c223b66d5e7172388d5d1fad6b7d135fce800a2765b2029e9',
    'input_features': 42, 'decision_rule': 'predict', 'experimental_pcap_model_included': False,
    'requirements': 'requirements.txt', 'lock': 'requirements-lock.txt',
    'clean_install_verified_on_this_machine': bool(installation and installation['all_41_versions_match']),
    'clean_install_external_sources': ['https://pypi.org/simple/', 'https://files.pythonhosted.org/'],
    'another_physical_machine_verified': False,
    'requires_original_development_folder': False,
    'source_identification': 'No Git repository; byte-identical runtime copies recorded by SHA-256.'}
(PACKAGE / 'VERSIONES.json').write_text(json.dumps(versions, indent=2, ensure_ascii=False), encoding='utf-8')
text = '# Estado de verificación de esta entrega\n\n'
if not acceptance:
    text += 'Candidato preparado; comprobaciones de aceptación todavía en curso.\n'
else:
    text += f"Entorno nuevo creado con el Python base de Windows; 41 versiones fijadas comprobadas y pip check sin conflictos. {acceptance['tests_run']} pruebas de aceptación del paquete: {'APROBADAS' if acceptance['successful'] else 'CON FALLOS'}. Código operativo y modelo conservados sin cambios.\n\n"
    text += 'El entorno no hereda site-packages globales ni del entorno de desarrollo; los paquetes se descargaron sin caché desde los requisitos incluidos. La prueba utiliza Python aislado y confirma que módulos y dependencias se importan de las ubicaciones esperadas. Se conserva el mismo intérprete base instalado en este Windows: no equivale a una prueba en otro equipo físico.\n\n'
if performance:
    text += '| Filas sintéticas | CSV bytes | Clasificación y scores (s) | Modelo (s) | Escritura final SQLite (s) | Reporte (s) | Pico RSS árbol (MiB) | Estado |\n|---:|---:|---:|---:|---:|---:|---:|---|\n'
    for case in performance['cases']:
        metrics = case.get('metrics', {})
        text += f"| {case['records']} | {metrics.get('input_bytes', '-')} | {metrics.get('classification_including_scores_seconds', 0):.3f} | {metrics.get('model_load_seconds', 0):.3f} | {metrics.get('sqlite_complete_and_alerts_seconds', 0):.3f} | {metrics.get('report_build_and_serialization_seconds', 0):.3f} | {case['parent_observed_peak_rss_bytes']/1024**2:.1f} | {case['status']} |\n"
    text += '\nCada proceso tuvo un límite de 120 s y 1,5 GiB RSS. Se exigieron al menos 4 GiB disponibles antes de cada lote. El RSS externo suma el lanzador de Windows y sus descendientes cada 50 ms: es una suma conservadora, no memoria física única. 10.000 filas es un lote de referencia offline; 50.000 es exploratorio. Los datos son sintéticos y las pruebas no miden precisión, concurrencia ni garantizan rendimiento a 100 MiB. La medición de reporte abarca construcción y serialización con funciones y formato existentes, sin tiempo de renderizado/transmisión del navegador.\n\n'
if browser:
    text += f"Arranque real mediante el script del paquete: HTTP de salud en {browser['startup_health_seconds']:.3f} s; interfaz, análisis, revisión, historial y exportaciones verificados en navegador con SQLite nueva. Persistencia tras reinicio: {browser['history_survived_restart']}. Se comprobó otra ubicación con espacios y sin rutas de desarrollo en los archivos operativos.\n\n"
text += 'Las versiones y resultados anteriores se refieren a este equipo Windows 11. Pendiente: otro equipo físico, instalación offline (no se incluyen wheels), carga real representativa del despliegue y concurrencia. No hay autenticación ni captura en vivo; el modelo PCAP permanece fuera de la entrega. El comentario histórico del lock sobre instalación no verificada describe su creación previa; este registro informa el resultado posterior sin alterar ese archivo.\n\n'
text += 'Los resultados de detección no se validaron con tráfico real ni etiquetas nuevas. El fixture solo comprueba consistencia. No se garantiza ausencia de defectos ni de vulnerabilidades. Consulte [README.md](README.md) y [RECUPERACION.md](RECUPERACION.md).\n'
(PACKAGE / 'VERIFICACION.md').write_text(text, encoding='utf-8')
files = []
for path in sorted(PACKAGE.rglob('*')):
    if not path.is_file() or path.name == 'manifest.sha256.json':
        continue
    assert '__pycache__' not in path.parts and '.venv' not in path.parts
    assert path.suffix not in {'.sqlite3', '.pcap', '.pcapng', '.log', '.zip', '.pyc'}
    with path.open('rb') as handle:
        digest = hashlib.file_digest(handle, 'sha256').hexdigest()
    files.append({'path': path.relative_to(PACKAGE).as_posix(), 'size_bytes': path.stat().st_size, 'sha256': digest})
manifest = {'manifest_version': 1, 'delivery_id': versions['delivery_id'],
    'generated_at_utc': datetime.now(timezone.utc).isoformat(), 'hash_algorithm': 'SHA-256',
    'self_excluded': 'manifest.sha256.json', 'files': files,
    'runtime_generated_excluded': ['.venv/', '__pycache__/', 'data/processed/*.sqlite3', 'respaldos_locales/'],
    'trust_notice': 'Manifest detects changes; it does not authenticate its publisher. Load only trusted joblib models.'}
(PACKAGE / 'manifest.sha256.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
print(json.dumps({'package_files': len(files) + 1, 'size_bytes': sum(row['size_bytes'] for row in files), 'clean_install_verified': versions['clean_install_verified_on_this_machine']}))
