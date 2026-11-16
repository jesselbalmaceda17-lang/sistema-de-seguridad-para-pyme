"""Add the physical verification evidence without changing application code or the old ZIP."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
PRIOR = ROOT / 'docs/monitoreo_20261109/cierre_001'
PYTHON = ROOT / '_delivery_validation/venv_entrega/Scripts/python.exe'


def sha(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def main():
    import psutil
    previous = json.loads((PRIOR / 'zip_final.json').read_text(encoding='utf-8'))
    physical = json.loads((OUT / 'resultado.json').read_text(encoding='utf-8'))
    regressions = json.loads((OUT / 'regresiones.json').read_text(encoding='utf-8'))
    acceptance = json.loads((OUT / 'csv_aceptacion/resultados.json').read_text(encoding='utf-8'))
    assert physical['passed'] and all(r['exit_code'] == 0 for r in regressions) and acceptance['successful']
    assert sha(Path(previous['zip'])) == previous['sha256']
    base = Path(previous['extracted_package'])
    package = ROOT / 'dist/SeguridadInteligentePYMES-monitoreo-wifi-verificado-20261109'
    assert package.resolve().parent == (ROOT / 'dist').resolve()
    shutil.copytree(base, package)
    shutil.copy2(OUT / 'VERIFICACION_WIFI.md', package / 'VERIFICACION_WIFI.md')
    summary = {k:physical[k] for k in ['utc','passed','interface_name','interface_description','interface_id',
        'type','sqlite_integrity','pcap_sha256','link_encapsulations','protocols',
        'all_38_features_recomputed_for_flows','https_requests_successful','duplicate_alert_ids',
        'capture_processes_remaining','original_models_and_databases_verified','source_changes','scope_limit']}
    summary.update(duration_seconds=physical['counters']['elapsed_seconds'],packets=physical['counters']['packets_accepted'],
        connections=physical['counters']['connections_observed'],segments=physical['counters']['flows_persisted'],
        alerts=len(physical['alerts']),current_monitoring_tests=38,current_csv_acceptance_tests=7,
        previous_complete_suite_tests=273,complete_suite_reused_with_identical_code=True)
    (package / 'validacion_wifi.json').write_text(json.dumps(summary,indent=2,ensure_ascii=False),encoding='utf-8')
    readme = package / 'README.md'
    readme.write_text(readme.read_text(encoding='utf-8') + '\n\n## Comprobación física adicional\n\nWi-Fi verificada desde Streamlit en esta computadora: 18,28 s, 315 paquetes IPv4, 23 conexiones, 24 segmentos y ninguna alerta. Ver [alcance y resultados](VERIFICACION_WIFI.md) y [resumen verificable](validacion_wifi.json). Código y modelo idénticos a la entrega anterior. Ethernet y otras redes requieren su propia comprobación autorizada.\n',encoding='utf-8')
    verification = package / 'VERIFICACION.md'
    content = verification.read_text(encoding='utf-8')
    content = content.replace('visibilidad de Wi-Fi/Ethernet', 'visibilidad de Ethernet y de otros entornos Wi-Fi')
    content += '\n\n## Ampliación posterior: interfaz física\n\nLa Wi-Fi activa de esta computadora también superó la prueba real desde Streamlit. Ver [verificación Wi-Fi](VERIFICACION_WIFI.md). Esta ampliación conserva sin cambios el código probado; las limitaciones de otros equipos, Ethernet y eficacia en producción permanecen.\n'
    verification.write_text(content,encoding='utf-8')
    versions = package / 'VERSIONES.json'
    metadata = json.loads(versions.read_text(encoding='utf-8'))
    metadata.update(release='monitoreo-wifi-verificado-20261109',physical_wifi_verified=True,
        physical_ethernet_verified=False,npcap_version_verified='1.88',application_code_changed=False)
    versions.write_text(json.dumps(metadata,indent=2),encoding='utf-8')
    allowed = {'README.md','VERIFICACION.md','VERSIONES.json','VERIFICACION_WIFI.md','validacion_wifi.json','manifest.sha256.json'}
    for path in package.rglob('*'):
        if path.is_file() and path.relative_to(package).as_posix() not in allowed:
            assert sha(path) == sha(base / path.relative_to(package))
    rows = []
    for path in sorted(package.rglob('*')):
        if path.is_file() and path.name != 'manifest.sha256.json':
            assert '__pycache__' not in path.parts and path.suffix not in {'.pyc','.sqlite3','.pcapng'}
            rows.append({'path':path.relative_to(package).as_posix(),'size_bytes':path.stat().st_size,'sha256':sha(path)})
    (package / 'manifest.sha256.json').write_text(json.dumps({'manifest_version':1,
        'generated_at_utc':datetime.now(timezone.utc).isoformat(),'hash_algorithm':'SHA-256',
        'self_excluded':'manifest.sha256.json','files':rows,
        'trust_notice':'Hashes check integrity, not publisher identity. Only load trusted models.'},indent=2),encoding='utf-8')
    archive = package.with_suffix('.zip')
    with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED,compresslevel=6) as target:
        for path in sorted(package.rglob('*')):
            if path.is_file():
                target.write(path,package.name+'/'+path.relative_to(package).as_posix())
    verify_archive(package, base, previous, summary)


def verify_archive(package, base, previous, summary):
    import psutil
    archive = package.with_suffix('.zip')
    digest = sha(archive)
    archive.with_suffix('.zip.sha256').write_text(f'{digest}  {archive.name}\n',encoding='ascii')
    # Keep the Windows path below MAX_PATH; the earlier nested location exceeded it.
    independent = Path(r'C:\Users\Ideapad15-itl6\AppData\Local\Temp\vscode-agent-codex-sandbox-Le0Mxc') / 'wifi-final'
    independent.mkdir(exist_ok=False)
    assert not independent.resolve().is_relative_to(ROOT)
    with zipfile.ZipFile(archive) as source:
        assert source.testzip() is None
        assert all((independent/n).resolve().is_relative_to(independent.resolve()) for n in source.namelist())
        source.extractall(independent)
    extracted = independent / package.name
    for path in package.rglob('*'):
        if path.is_file():
            assert sha(path) == sha(extracted/path.relative_to(package))
    checked = subprocess.run([str(PYTHON),'-I','-B',str(extracted/'herramientas/verificar_paquete.py')],
        cwd=independent,capture_output=True,text=True,check=True,timeout=15)
    captures = [p.info for p in psutil.process_iter(['pid','name']) if p.info['name'].lower() in {'tshark.exe','dumpcap.exe'}]
    assert not captures and sha(Path(previous['zip'])) == previous['sha256']
    result = {'zip':str(archive),'bytes':archive.stat().st_size,'sha256':digest,'crc_ok':True,
        'independent_extraction':str(extracted),'manifest':json.loads(checked.stdout),
        'application_and_model_byte_identical_to_tested_package':True,'old_zip_unchanged':True,
        'old_zip_sha256':previous['sha256'],'capture_processes_remaining':captures,
        'documentation_only_update':True,'physical_result':summary,
        'validation_harness_note':'Initial extraction path exceeded Windows MAX_PATH; repeated in a shorter independent location without changing application code.'}
    (OUT/'paquete_final.json').write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='physical_result'}),flush=True)


if __name__ == '__main__':
    if '--verify-existing' in sys.argv:
        previous = json.loads((PRIOR/'zip_final.json').read_text(encoding='utf-8'))
        package = ROOT/'dist/SeguridadInteligentePYMES-monitoreo-wifi-verificado-20261109'
        summary = json.loads((package/'validacion_wifi.json').read_text(encoding='utf-8'))
        verify_archive(package,Path(previous['extracted_package']),previous,summary)
    else:
        main()
