"""Verify approved differences, all protected inputs and SQLite after tests."""
from contextlib import closing
from datetime import datetime, timezone
import difflib
import hashlib
import json
from pathlib import Path
import sqlite3
import zipfile

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = Path(__file__).resolve().parent
ALLOWED = {"seguridad_pymes/zeek_labels.py", "tests/test_iot23_acquisition_compatibility.py"}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    backup_record = json.loads((OUTPUT / "respaldo.json").read_text(encoding="utf-8"))
    archive_path = ROOT / backup_record["backup"]
    assert sha(archive_path) == backup_record["sha256"]
    unchanged, changed, databases, patch = [], [], [], []
    with zipfile.ZipFile(archive_path) as archive:
        assert archive.testzip() is None
        manifest = json.loads(archive.read("BACKUP_MANIFEST.json"))
        for entry in manifest["files"]:
            path = ROOT / entry["path"]
            actual = sha(path)
            item = {"path": entry["path"], "before_sha256": entry["source_sha256"], "after_sha256": actual}
            if actual != entry["source_sha256"]:
                assert entry["path"] in ALLOWED, entry["path"]
                changed.append(item)
                patch.extend(difflib.unified_diff(archive.read(entry["path"]).decode("utf-8").splitlines(keepends=True),
                    path.read_text(encoding="utf-8").splitlines(keepends=True),
                    fromfile="before/" + entry["path"], tofile="after/" + entry["path"]))
            else:
                unchanged.append(item)
            if path.suffix == ".sqlite3":
                with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as database:
                    messages = [r[0] for r in database.execute("PRAGMA integrity_check")]
                assert messages == ["ok"] and sha(path) == actual
                databases.append({"path": entry["path"], "integrity": "ok", "source_unchanged": True})
    assert {x["path"] for x in changed} == ALLOWED
    for entry in manifest["preserved_backups"]:
        assert sha(ROOT / entry["path"]) == entry["sha256"]
        with zipfile.ZipFile(ROOT / entry["path"]) as previous:
            assert previous.testzip() is None
    for scope in ("especificas", "completas"):
        report = json.loads((OUTPUT / ("resultado_" + scope + ".json")).read_text(encoding="utf-8"))
        assert report["successful"] and report["failures"] == report["errors"] == report["skipped"] == 0
    with (OUTPUT / "cambios.diff").open("x", encoding="utf-8") as stream:
        stream.write("".join(patch))
    result = {"checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "git": "not a Git repository", "baseline_file_count": len(manifest["files"]),
        "protected_files_unchanged": len(unchanged), "unchanged_files": unchanged,
        "modified_existing_files": changed, "deleted_existing_files": [],
        "preserved_backups": manifest["preserved_backups"], "new_backup": backup_record,
        "sqlite_integrity": databases}
    with (OUTPUT / "integridad.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
    print("Protected unchanged:", len(unchanged), "Approved modified:", len(changed), "SQLite OK:", len(databases))


if __name__ == "__main__":
    main()
