"""Summarize clean installation and publicly downloaded dependency artifacts."""
from datetime import datetime
import json
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
PACKAGE = ROOT / 'dist/SeguridadInteligentePYMES-entrega-20261109'
report = json.loads((OUT / 'instalacion_paquete_pip.json').read_text(encoding='utf-8'))
installed = []
for item in report['install']:
    download = item['download_info']
    assert download['url'].startswith('https://files.pythonhosted.org/'), download['url']
    installed.append({'name': item['metadata']['name'], 'version': item['metadata']['version'],
                      'url': download['url'], 'sha256': download['archive_info']['hashes']['sha256']})
assert len(installed) == 41
(PACKAGE / 'DEPENDENCIAS_DESCARGADAS.json').write_text(json.dumps({'scope': 'Artifacts downloaded by pip for the clean Windows 11 / CPython 3.14 x64 verification. No wheel files shipped. Existing requirements files remain unchanged.', 'artifacts': installed}, indent=2), encoding='utf-8')
environment = ROOT / '_delivery_validation/venv_entrega'
env_bytes = sum(path.stat().st_size for path in environment.rglob('*') if path.is_file())
log = (OUT / 'instalacion_paquete_pip.log').read_text(encoding='utf-8')
times = re.findall(r'(?m)^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)', log)
duration = (datetime.fromisoformat(times[-1]) - datetime.fromisoformat(times[0])).total_seconds() if times else None
result = {'downloaded_artifacts': len(installed), 'no_cache_dir': True, 'system_site_packages': False,
          'user_site_disabled_during_tests': True, 'created_from_base_launcher': 'py -3.14 -m venv _delivery_validation/venv_entrega',
          'requirements_source': 'The two byte-identical requirement files inside the delivery package',
          'internet_dependencies': ['pypi.org', 'files.pythonhosted.org'],
          'pip_install_log_elapsed_seconds_approx': duration, 'virtual_environment_size_bytes': env_bytes,
          'disk_free_bytes_after_tests': shutil.disk_usage(ROOT).free,
          'preliminary_environment': '_delivery_validation/venv_clean was a separate preliminary install, not the environment used for final package verification; final environment was independently created by the base Python launcher.',
          'another_physical_machine': False}
(OUT / 'resumen_instalacion.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps(result))
