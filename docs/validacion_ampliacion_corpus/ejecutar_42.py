"""One authorized full scenario; unchanged extractor/importer/auditor, no model."""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from seguridad_pymes.iot23_sources import _fetch
from seguridad_pymes.pcap_extract import extract_capture
from seguridad_pymes.pcap_schema import ExtractionConfig
from seguridad_pymes.label_audit import audit_files
from analizar_grupos import group_census
from seleccionar import head
import psutil

OUTPUT = Path(__file__).resolve().parent
SCENARIO = "CTU-IoT-Malware-Capture-42-1"
FOLDER = "iot23_trojan_42_1"
CAPTURE = "2019-01-10-14-34-38-192.168.1.197.pcap"
TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")
RAW = ROOT / "data/raw" / FOLDER
PROCESSED = ROOT / "data/processed" / FOLDER
SPEC = importlib.util.spec_from_file_location("previous_resource_measurement", ROOT / "docs/validacion_adquisicion_iot23_8_4/ejecutar_etapa.py")
RESOURCES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RESOURCES)


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(content):
    return hashlib.sha256(content).hexdigest()


def save(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(content, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def acquire():
    if RAW.exists():
        raise ValueError("Acquisition directory exists; never overwrite sources")
    selection = json.loads((OUTPUT / "seleccion_fuentes.json").read_text(encoding="utf-8"))
    selected = next(s for s in selection["scenarios"] if s["scenario"] == SCENARIO)
    verified = []
    for entry in selected["files_head"]:
        current = head(entry["url"])
        if current["size_bytes"] != entry["size_bytes"] or current["headers"].get("etag") != entry["headers"].get("etag"):
            raise ValueError("Publisher source changed since selection")
        verified.append(current)
    free = shutil.disk_usage(ROOT).free
    available_memory = psutil.virtual_memory().available
    if free < 512 * 1024**2 or available_memory < 1024**3:
        raise ValueError("Insufficient preflight headroom for small pilot")
    decision = {"decided_at_utc": utc(), "selected_scenario": SCENARIO,
        "only_data_files_authorized_for_this_acquisition": verified,
        "total_download_bytes": sum(x["size_bytes"] for x in verified),
        "free_disk_bytes": free, "available_physical_memory_bytes": available_memory,
        "disk_headroom_guard_bytes": 512 * 1024**2, "available_memory_guard_bytes": 1024**3,
        "configuration": ExtractionConfig().to_dict(), "resource_limit_changes": [],
        "audit_limits": {"max_pcap_bytes": 128 * 1024**2, "max_frames": 1000000},
        "reason": "Full 2.9 MB PCAP, 4,426 published references and six file-download-related malicious references; smaller test of non-SYN behavior than Muhstik, without changing limits",
        "muhstik_deferred": {"pair_bytes": 82303309, "published_reference_connections": 156103,
            "max_flows_current": 100000, "reason": "Zeek counts are not extractor counts, but many scan references risk exceeding max_flows; Python objects/JSON may require several GiB. No limits raised and no data body requested."},
        "source_advisories": ["README generic dataset number says 41 although official directory and links are 42-1", "README start year says 2018 but dated timeline and capture filename say January 2019; preserve exact metadata and validate packet correspondence", "Full Zenodo archive byte identity is not verified; official IndividualScenarios snapshot only"],
        "reserved_not_requested": selection["reserved_not_requested"],
        "do_not_download_alternative_subsets": ["test.pcap", "only5000", "telnet.pcap", "port-filtered files"]}
    save(OUTPUT / "decision_previa.json", decision)  # Persist BEFORE any data GET.
    RAW.mkdir(parents=True)
    files = []
    started = time.perf_counter()
    for entry in verified:
        content, transport = _fetch(entry["url"], entry["size_bytes"])
        if len(content) != entry["size_bytes"]:
            raise ValueError("Actual body length differs from verified HEAD")
        name = entry["url"].rsplit("/", 1)[-1]
        role = "pcap" if name == CAPTURE else "labels"
        if role == "pcap" and content[:4] not in RESOURCES.PCAP_MAGIC:
            raise ValueError("Not a classic PCAP")
        if role == "labels" and (b"#fields" not in content or b"detailed-label" not in content):
            raise ValueError("Not a labeled Zeek log")
        with (RAW / name).open("xb") as stream:
            stream.write(content)
        files.append({"role": role, "local_name": name, **transport})
        save(RAW / (role + "_transport.json"), files[-1])
    save(RAW / "provenance.json", {"manifest_version": "sipymes.iot23.sources.v1",
        "scenario": SCENARIO, "obtained_at_utc": utc(), "files": files,
        "dataset_release": "IoT-23 1.0.0 official IndividualScenarios snapshot",
        "release_citation": "https://zenodo.org/records/4743746",
        "pair_verification": "Both full capture and labeled log linked in same official scenario directory; readonly packet audit independently determines admissibility",
        "metadata_evidence_sha256": sha((OUTPUT / "seleccion_fuentes.json").read_bytes()),
        "decision_previa_sha256": sha((OUTPUT / "decision_previa.json").read_bytes()),
        "source_advisories": decision["source_advisories"],
        "acquisition_wall_seconds": time.perf_counter()-started})
    print(json.dumps(files, indent=2), flush=True)


def process():
    if PROCESSED.exists():
        raise ValueError("Processing directory exists; preserve prior results")
    PROCESSED.mkdir(parents=True)
    stop, samples, errors = threading.Event(), [], []
    def sample():
        parent = psutil.Process()
        while not stop.is_set():
            try:
                rss = 0
                for p in [parent] + parent.children(recursive=True):
                    try:
                        rss += p.memory_info().rss
                    except psutil.NoSuchProcess:
                        pass
                samples.append(rss)
            except psutil.Error as error:
                errors.append(str(error))
            stop.wait(0.02)
    thread = threading.Thread(target=sample, daemon=True)
    thread.start()
    start, cpu = time.perf_counter(), time.process_time()
    execution = {"started_at_utc": utc(), "scenario": SCENARIO,
        "configuration": ExtractionConfig().to_dict(), "resource_limit_changes": [], "stages": []}
    capture = RAW / CAPTURE
    try:
        version = subprocess.run([str(TSHARK), "--version"], capture_output=True, check=True, timeout=15)
        execution["tshark_version"] = version.stdout.decode("utf-8", errors="replace")
        if "4.6.9" not in execution["tshark_version"].splitlines()[0]:
            raise ValueError("Unexpected TShark version")
        timer = time.perf_counter()
        command = [str(TSHARK), "-n", "-r", str(capture), "-T", "fields", "-e", "frame.number"]
        read = subprocess.run(command, capture_output=True, timeout=120)
        execution["complete_tshark_read"] = {"command": command, "exit_code": read.returncode,
            "frames": len(read.stdout.splitlines()), "stderr": read.stderr.decode("utf-8", errors="replace")}
        read.check_returncode()
        execution["stages"].append({"name": "complete_tshark_read", "wall_seconds": time.perf_counter()-timer})
        timer = time.perf_counter()
        extraction = extract_capture(capture, tshark_path=TSHARK)
        assert extraction["quality"]["packets_seen"] == execution["complete_tshark_read"]["frames"]
        assert len(extraction["feature_definitions"]) == 38
        save(PROCESSED / "extraction.json", extraction)
        execution["stages"].append({"name": "extraction_and_write", "wall_seconds": time.perf_counter()-timer})
        timer = time.perf_counter()
        audit = audit_files(PROCESSED / "extraction.json", RAW / "conn.log.labeled", RAW / "provenance.json",
                            PROCESSED / "audit_v2", capture_path=capture)
        execution["stages"].append({"name": "audit_v2_and_write", "wall_seconds": time.perf_counter()-timer})
        execution["audit_summary"] = audit["summary"]
        timer = time.perf_counter()
        save(OUTPUT / "censo_trojan_42_1.json", {"summary": audit["summary"], "quality": extraction["quality"],
            "groups": group_census(extraction, audit),
            "raw_storage_bytes": sum(p.stat().st_size for p in RAW.rglob("*") if p.is_file()),
            "processed_storage_bytes": sum(p.stat().st_size for p in PROCESSED.rglob("*") if p.is_file())})
        execution["stages"].append({"name": "descriptive_group_census", "wall_seconds": time.perf_counter()-timer})
        execution["successful"] = True
    except Exception as error:
        execution.update(successful=False, error=str(error), traceback=traceback.format_exc(),
                         next_step="Stop this scenario and diagnose; do not alter protected modules or truncate input")
        raise
    finally:
        stop.set()
        thread.join()
        execution.update(finished_at_utc=utc(), wall_seconds=time.perf_counter()-start,
            python_cpu_seconds=time.process_time()-cpu,
            memory={"python_os_peak_working_set_bytes": RESOURCES.windows_peak_working_set(),
                "sampled_python_and_children_rss_max_bytes": max(samples) if samples else None,
                "sampling_target_interval_seconds": 0.02, "samples": len(samples), "errors": errors,
                "method": "OS Python peak; separate sampled RSS sum including observed children. Not exact tree peak; census included."})
        save(OUTPUT / "ejecucion_trojan_42_1.json", execution)
        print(json.dumps({k: execution[k] for k in ("scenario", "successful", "wall_seconds", "memory")}, indent=2), flush=True)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["adquirir", "procesar"])
    args = parser.parse_args()
    acquire() if args.action == "adquirir" else process()
