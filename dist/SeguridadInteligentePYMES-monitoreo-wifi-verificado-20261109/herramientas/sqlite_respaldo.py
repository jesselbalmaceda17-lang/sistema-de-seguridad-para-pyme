"""Back up or restore SQLite to a NEW target using the SQLite backup API."""
import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import sys


def copy_database(source, target):
    source, target = Path(source).resolve(), Path(target).resolve()
    if not source.is_file():
        raise ValueError('La base de origen no existe o no es un archivo.')
    if target.exists() or source == target:
        raise ValueError('El destino debe ser nuevo. No se sobrescriben bases existentes.')
    if not target.parent.is_dir():
        raise ValueError('Cree primero la carpeta de destino.')
    with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)) as original:
        if original.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise ValueError('La base de origen no supera integrity_check.')
        # Exclusive creation prevents accidental replacement of an existing file.
        with target.open('xb'):
            pass
        with closing(sqlite3.connect(target)) as copied:
            original.backup(copied)
            if copied.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                raise ValueError('La copia no supera integrity_check; conservar para diagnostico.')
    with target.open('rb') as handle:
        sha = hashlib.file_digest(handle, 'sha256').hexdigest()
    return {'target': str(target), 'sha256': sha, 'integrity_check': 'ok', 'size_bytes': target.stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['backup', 'restore'])
    parser.add_argument('source', type=Path)
    parser.add_argument('target', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps({'operation': args.operation, **copy_database(args.source, args.target)}))
    except (OSError, sqlite3.Error, ValueError) as error:
        print(f'Operacion rechazada: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
