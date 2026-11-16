"""Verify the shipped files before loading a trusted serialized model."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def verify():
    manifest = json.loads((ROOT / 'manifest.sha256.json').read_text(encoding='utf-8'))
    for entry in manifest['files']:
        path = (ROOT / entry['path']).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file():
            raise ValueError(f"Archivo ausente o ruta invalida: {entry['path']}")
        with path.open('rb') as handle:
            actual = hashlib.file_digest(handle, 'sha256').hexdigest()
        if actual != entry['sha256'] or path.stat().st_size != entry['size_bytes']:
            raise ValueError(f"Hash o tamano diferente: {entry['path']}")
    print(json.dumps({'files_verified': len(manifest['files']), 'status': 'ok',
                      'notice': 'Hashes check integrity, not publisher identity. Only load trusted models.'}))


if __name__ == '__main__':
    try:
        verify()
    except (OSError, ValueError, KeyError) as error:
        print(f'Verificacion fallida: {error}', file=sys.stderr)
        raise SystemExit(2)
