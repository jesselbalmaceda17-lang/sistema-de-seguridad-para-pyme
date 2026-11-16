"""Reproducible, stage-scoped acquisition/measurement; never trains or predicts.

Only the two explicitly authorized source pairs are permitted. Product modules
are imported without edits. Run with the project's Python and -B from its root.
"""
from collections import Counter
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import lzma
from pathlib import Path
import shutil
import subprocess
import struct
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
EVIDENCE = Path(__file__).resolve().parent
TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")
BASE = "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/"
SCENARIOS = {
    "hakai": {"scenario": "CTU-IoT-Malware-Capture-8-1",
              "folder": "iot23_hakai_8_1",
              "capture": "2018-07-31-15-15-09-192.168.100.113.pcap",
              "download_size": 2098362, "labels_size": 1431000},
    "hue": {"scenario": "CTU-Honeypot-Capture-4-1",
            "folder": "iot23_hue_4_1",
            "capture": "2018-10-25-14-06-32-192.168.1.132.pcap",
            "download_size": 376840, "labels_size": 61653,
            "snapshot_pcap_sha256": "3fb775c0391b6ad313a3f7845e634a277b07c3f6377346c2486ba63e1c22e90c",
            "published_pcap_sha256": "f770897e6cc3fa45857aee25ef7d3ab39dba39127b5bb813e0e0d48d3b905347"},
}
PCAP_MAGIC = {bytes.fromhex(x) for x in ("d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d")}


def utc():
    return datetime.now(timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def verify_hue_header_difference(content, published_sha256):
    """Prove the publisher's digest differs ONLY at global-header snaplen.

    The diagnostic probe exists only in memory. Never alter PCAP bytes on disk.
    """
    if len(content) < 24 or content[:4] != bytes.fromhex("d4c3b2a1"):
        raise ValueError("Unexpected Hue PCAP format")
    if struct.unpack_from("<I", content, 16)[0] != 65535:
        raise ValueError("Unexpected Hue global snaplen")
    probe = content[:16] + struct.pack("<I", 262144) + content[20:]
    if digest(probe) != published_sha256:
        raise ValueError("Publisher discrepancy extends beyond the documented snaplen field")
    return {"published_sha256": published_sha256, "actual_byte_identity": False,
            "packet_records_identical_to_published_digest": True,
            "only_difference": "global PCAP header snaplen at offsets 16..19",
            "observed_snaplen": 65535, "publisher_snaplen": 262144,
            "diagnostic_probe_sha256": digest(probe), "probe_written_to_disk": False}


def decompress_xz_capture(source, destination, *, maximum_bytes=16 * 1024**2,
                          expected_sha256=None, publisher_header_sha256=None):
    """One XZ stream, bounded output/dictionary, no extraction paths/overwrites.

    Validate CRC, EOF, no trailing/concatenated streams, PCAP magic and optional
    published digest before creating any output. Leave the original XZ intact.
    """
    source, destination = Path(source), Path(destination)
    if destination.exists():
        raise ValueError("Destination already exists")
    # Hue's LZMA2 property 0x1c declares a 64 MiB dictionary, plus decoder
    # overhead. 96 MiB is a bounded acquisition-only guard, not a core limit.
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=96 * 1024**2)
    content = decoder.decompress(source.read_bytes(), max_length=maximum_bytes + 1)
    if len(content) > maximum_bytes:
        raise ValueError("Decompressed output exceeds explicit 16 MiB acquisition guard")
    if not decoder.eof or decoder.unused_data:
        raise ValueError("Incomplete XZ or trailing/concatenated data")
    if len(content) < 24 or content[:4] not in PCAP_MAGIC:
        raise ValueError("Decompressed content is not classic PCAP")
    checksum = digest(content)
    if expected_sha256 is not None and checksum != expected_sha256:
        raise ValueError("Decompressed PCAP differs from expected SHA-256")
    publisher_check = (verify_hue_header_difference(content, publisher_header_sha256)
                       if publisher_header_sha256 is not None else None)
    with destination.open("xb") as stream:
        stream.write(content)
    return {"size_bytes": len(content), "sha256": checksum,
            "source_xz_sha256": digest(source.read_bytes()),
            "output_limit_bytes": maximum_bytes, "lzma_memlimit_bytes": 96 * 1024**2,
            "expected_sha256_verified": expected_sha256 is not None,
            "publisher_header_verification": publisher_check}


def acquire():
    from seguridad_pymes.iot23_sources import _fetch
    if any((ROOT / "data/raw" / s["folder"]).exists() for s in SCENARIOS.values()):
        raise ValueError("Acquisition directories must be new; never overwrite data")
    metadata, heads = {}, []
    for key, scenario in SCENARIOS.items():
        base = BASE + scenario["scenario"] + "/"
        info = {}
        sources = [("scenario_index", base), ("labels_index", base + "bro/"),
                   ("readme", base + "README.md")]
        if key == "hue":
            sources.append(("capinfos", base + scenario["capture"].replace(".pcap", ".capinfos")))
        for kind, url in sources:
            content, transport = _fetch(url, 200_000)
            info[kind] = {"text": content.decode("utf-8"), **transport}
        download_name = scenario["capture"] + (".xz" if key == "hue" else "")
        if (download_name not in info["scenario_index"]["text"]
                or 'href="bro/"' not in info["scenario_index"]["text"]
                or "conn.log.labeled" not in info["labels_index"]["text"]
                or ("192.168.100.113" if key == "hakai" else "192.168.1.132") not in info["readme"]["text"]):
            raise ValueError("Official scenario/file association not established")
        if key == "hue" and scenario["published_pcap_sha256"] not in info["capinfos"]["text"]:
            raise ValueError("Publisher Hue digest changed; investigate before downloading")
        metadata[key] = info
        for role, name, size in (("pcap_xz" if key == "hue" else "pcap", download_name, scenario["download_size"]),
                                 ("labels", "bro/conn.log.labeled", scenario["labels_size"])):
            url = base + name
            command = ["curl.exe", "--head", "--fail", "--silent", "--show-error", "--proto", "=https", "--max-time", "30", url]
            completed = subprocess.run(command, capture_output=True, check=True, timeout=40)
            header_text = completed.stdout.decode("iso-8859-1")
            lengths = [int(line.split(":", 1)[1]) for line in header_text.splitlines()
                       if line.lower().startswith("content-length:")]
            if lengths != [size] or "200 OK" not in header_text:
                raise ValueError("HEAD size/status changed; reassess before acquisition")
            heads.append({"scenario": scenario["scenario"], "role": role, "url": url,
                          "size_bytes": size, "checked_at_utc": utc(), "raw_headers": header_text})
    free = shutil.disk_usage(ROOT).free
    # 4 MB download + <16 MB decompression + bounded artifacts/backup headroom.
    required_headroom = 512 * 1024**2
    if free < required_headroom:
        raise ValueError("Insufficient free space for bounded stage")
    save_json(EVIDENCE / "preflight.json", {"checked_at_utc": utc(), "files": heads,
        "download_total_bytes": sum(x["size_bytes"] for x in heads),
        "free_bytes_before_download": free, "required_headroom_bytes": required_headroom,
        "metadata": metadata,
        "release": "IoT-23 1.0.0 official IndividualScenarios snapshot; archive byte identity not claimed",
        "official_documentation": "https://www.stratosphereips.org/datasets-iot23",
        "release_citation": "https://zenodo.org/records/4743746"})
    for key, scenario in SCENARIOS.items():
        start = time.perf_counter()
        destination = ROOT / "data/raw" / scenario["folder"]
        destination.mkdir(parents=True)
        files = []
        for entry in (x for x in heads if x["scenario"] == scenario["scenario"]):
            content, transport = _fetch(entry["url"], entry["size_bytes"])
            if len(content) != entry["size_bytes"]:
                raise ValueError("Actual download differs from preflight length")
            if entry["role"] == "pcap" and content[:4] not in PCAP_MAGIC:
                raise ValueError("Not a classic PCAP")
            if entry["role"] == "labels" and (b"#fields" not in content or b"detailed-label" not in content):
                raise ValueError("Not a labeled Zeek log")
            name = entry["url"].rsplit("/", 1)[-1]
            with (destination / name).open("xb") as stream:
                stream.write(content)
            files.append({"role": entry["role"], "local_name": name, **transport})
        save_json(destination / "acquisition_transport.json", {"files": files})
        if key == "hue":
            derived = decompress_xz_capture(destination / (scenario["capture"] + ".xz"),
                destination / scenario["capture"], expected_sha256=scenario["snapshot_pcap_sha256"],
                publisher_header_sha256=scenario["published_pcap_sha256"])
            files.append({"role": "pcap", "local_name": scenario["capture"],
                          "derived_at_utc": utc(), "derivation": "lossless XZ decompression",
                          "url": heads[2]["url"], **derived})
        save_json(destination / "provenance.json", {
            "manifest_version": "sipymes.iot23.sources.v1", "scenario": scenario["scenario"],
            "dataset_release": "IoT-23 1.0.0; official IndividualScenarios snapshot",
            "obtained_at_utc": utc(), "acquisition_elapsed_seconds": time.perf_counter() - start,
            "pair_verification": "Official scenario and bro indices, README and capinfos preserved in preflight; actual correspondence separately audited",
            "archive_byte_identity": "not checked; full archive not acquired",
            "preflight_sha256": digest((EVIDENCE / "preflight.json").read_bytes()), "files": files})
        print(key, [(x["role"], x["size_bytes"], x["sha256"]) for x in files], flush=True)


def recover_hue():
    """Recover the interrupted acquisition without overwriting either download.

    Initial transport metadata was lost on the first decompression exception;
    re-fetch only the same two authorized URLs and require byte identity.
    """
    from seguridad_pymes.iot23_sources import _fetch
    scenario = SCENARIOS["hue"]
    raw = ROOT / "data/raw" / scenario["folder"]
    preflight = json.loads((EVIDENCE / "preflight.json").read_text(encoding="utf-8"))
    if (raw / "provenance.json").exists() or (raw / scenario["capture"]).exists():
        raise ValueError("Hue acquisition already complete; recovery must not overwrite")
    start = time.perf_counter()
    transport_path = raw / "acquisition_transport.json"
    if transport_path.exists():
        files = json.loads(transport_path.read_text(encoding="utf-8"))["files"]
        allowed = {x["url"]: x for x in preflight["files"] if x["scenario"] == scenario["scenario"]}
        if {x["url"] for x in files} != set(allowed):
            raise ValueError("Recovery transport URLs differ from preflight")
        for entry in files:
            content = (raw / entry["local_name"]).read_bytes()
            if digest(content) != entry["sha256"] or len(content) != allowed[entry["url"]]["size_bytes"]:
                raise ValueError("Retained file differs from verified transport")
    else:
        files = []
        for entry in (x for x in preflight["files"] if x["scenario"] == scenario["scenario"]):
            name = entry["url"].rsplit("/", 1)[-1]
            content, transport = _fetch(entry["url"], entry["size_bytes"])
            if content != (raw / name).read_bytes():
                raise ValueError("Reverified download differs from retained original")
            files.append({"role": entry["role"], "local_name": name,
                "initial_local_file_mtime_utc": datetime.fromtimestamp((raw / name).stat().st_mtime, timezone.utc).isoformat(),
                "transport_metadata_note": "Same official URL retrieved again and byte equality verified; original file retained", **transport})
        save_json(transport_path, {"files": files,
            "additional_verification_download_bytes": sum(x["size_bytes"] for x in files)})
    decomp_start = time.perf_counter()
    derived = decompress_xz_capture(raw / (scenario["capture"] + ".xz"), raw / scenario["capture"],
                                   expected_sha256=scenario["snapshot_pcap_sha256"],
                                   publisher_header_sha256=scenario["published_pcap_sha256"])
    files.append({"role": "pcap", "local_name": scenario["capture"], "derived_at_utc": utc(),
        "derivation": "lossless XZ decompression", "url": files[0]["url"], **derived})
    save_json(raw / "provenance.json", {"manifest_version": "sipymes.iot23.sources.v1",
        "scenario": scenario["scenario"], "dataset_release": "IoT-23 1.0.0; official IndividualScenarios snapshot",
        "obtained_at_utc": utc(), "recovery_elapsed_seconds": time.perf_counter()-start,
        "decompression_elapsed_seconds": time.perf_counter()-decomp_start,
        "recovery_python_peak_working_set_bytes": windows_peak_working_set(),
        "pair_verification": "Official indices, README and capinfos in preflight; publisher digest discrepancy proven limited to global snaplen header; actual label correspondence separately audited",
        "archive_byte_identity": "not checked; full archive not acquired",
        "preflight_sha256": digest((EVIDENCE / "preflight.json").read_bytes()), "files": files})
    print(json.dumps(files, indent=2))


def windows_peak_working_set():
    from ctypes import wintypes
    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
            (name, ctypes.c_size_t) for name in ("PeakWorkingSetSize", "WorkingSetSize",
            "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
            "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]
    current = ctypes.windll.kernel32.GetCurrentProcess
    current.restype = wintypes.HANDLE
    query = ctypes.windll.psapi.GetProcessMemoryInfo
    query.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    counters = Counters()
    counters.cb = ctypes.sizeof(counters)
    if not query(current(), ctypes.byref(counters), counters.cb):
        raise ctypes.WinError()
    return counters.PeakWorkingSetSize


def process_scenario(key):
    from seguridad_pymes.pcap_extract import extract_capture
    from seguridad_pymes.label_audit import audit_files
    from seguridad_pymes.pcap_schema import ExtractionConfig
    import psutil  # Already present in this environment; no installation.
    scenario = SCENARIOS[key]
    raw = ROOT / "data/raw" / scenario["folder"]
    capture = raw / scenario["capture"]
    output = ROOT / "data/processed" / scenario["folder"]
    if output.exists():
        raise ValueError("Choose a new processing directory; existing results preserved")
    output.mkdir(parents=True)
    stop = threading.Event()
    samples = []
    sample_errors = []
    def sample():
        parent = psutil.Process()
        while not stop.is_set():
            try:
                processes = [parent] + parent.children(recursive=True)
                rss = 0
                for child in processes:
                    try:
                        rss += child.memory_info().rss
                    except psutil.NoSuchProcess:
                        pass
                samples.append(rss)
            except psutil.Error as error:
                sample_errors.append(str(error))
            stop.wait(0.02)
    thread = threading.Thread(target=sample, daemon=True)
    thread.start()
    start, cpu = time.perf_counter(), time.process_time()
    execution = {"scenario": scenario["scenario"], "started_at_utc": utc(),
        "python": sys.version, "configuration": ExtractionConfig().to_dict(),
        "resource_configuration_changes": [], "stages": []}
    try:
        version = subprocess.run([str(TSHARK), "--version"], capture_output=True, check=True, timeout=15)
        execution["tshark_version"] = version.stdout.decode("utf-8", errors="replace")
        if "4.6.9" not in execution["tshark_version"].splitlines()[0]:
            raise ValueError("Unexpected TShark version; investigate before processing")
        stage = time.perf_counter()
        command = [str(TSHARK), "-n", "-r", str(capture), "-T", "fields", "-e", "frame.number"]
        verified = subprocess.run(command, capture_output=True, timeout=120)
        execution["tshark_read"] = {"command": command, "exit_code": verified.returncode,
            "packets": len(verified.stdout.splitlines()),
            "stderr": verified.stderr.decode("utf-8", errors="replace")}
        verified.check_returncode()
        execution["stages"].append({"stage": "complete_tshark_read", "wall_seconds": time.perf_counter()-stage})
        stage = time.perf_counter()
        extraction = extract_capture(capture, tshark_path=TSHARK)
        if extraction["quality"]["packets_seen"] != execution["tshark_read"]["packets"]:
            raise ValueError("Extractor and independent complete read counts disagree")
        save_json(output / "extraction.json", extraction)
        execution["stages"].append({"stage": "extraction_and_serialization", "wall_seconds": time.perf_counter()-stage})
        del extraction
        stage = time.perf_counter()
        audited = audit_files(output / "extraction.json", raw / "conn.log.labeled", raw / "provenance.json",
                              output / "audit_v2", capture_path=capture)
        execution["stages"].append({"stage": "audit_v2_and_serialization", "wall_seconds": time.perf_counter()-stage})
        execution["audit_summary"] = audited["summary"]
        execution["successful"] = True
    except Exception as error:
        execution.update(successful=False, error=repr(error), traceback=traceback.format_exc(),
                         next_step="Read-only diagnosis; do not modify extractor or auditor")
        raise
    finally:
        execution.update(finished_at_utc=utc(), wall_seconds=time.perf_counter()-start,
                         python_cpu_seconds=time.process_time()-cpu)
        stop.set()
        thread.join()
        execution["memory"] = {"python_os_peak_working_set_bytes": windows_peak_working_set(),
            "sampled_python_and_children_rss_max_bytes": max(samples) if samples else None,
            "sampling_interval_seconds": 0.02, "samples": len(samples), "sampling_errors": sample_errors,
            "method": "Windows process high-water mark for Python; separate sampled sum of Python and child RSS (includes TShark when observed), not an exact tree peak"}
        save_json(EVIDENCE / (key + "_ejecucion.json"), execution)
        print(json.dumps(execution, indent=2), flush=True)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["acquire", "recover-hue", "hakai", "hue"])
    args = parser.parse_args()
    if args.action == "acquire":
        acquire()
    elif args.action == "recover-hue":
        recover_hue()
    else:
        process_scenario(args.action)
