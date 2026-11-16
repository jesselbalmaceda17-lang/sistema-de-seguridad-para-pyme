"""Bounded acquisition of exactly one official IoT-23 v1 scenario, never the archive."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


SCENARIO = "CTU-IoT-Malware-Capture-20-1"
ROOT = "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/"
BASE = ROOT + "IndividualScenarios/" + SCENARIO + "/"
PCAP_NAME = "2018-10-02-13-12-30-192.168.100.103.pcap"
PCAP_URL = BASE + PCAP_NAME
LABEL_URL = BASE + "bro/conn.log.labeled"


def _fetch(url, maximum_bytes):
    """Windows curl validates HTTPS via the OS certificate store (no --insecure)."""
    executable = shutil.which("curl.exe") or shutil.which("curl")
    if not executable:
        raise ValueError("Windows curl is required for this bounded download")
    marker = b"\n__SIPYMES_CURL_METADATA__"
    with tempfile.TemporaryDirectory(prefix="sipymes-source-") as directory:
        headers_path = Path(directory) / "headers.txt"
        command = [executable, "--fail", "--silent", "--show-error", "--proto", "=https",
                   "--max-time", "60", "--max-filesize", str(maximum_bytes),
                   "--dump-header", str(headers_path), "--write-out",
                   marker.decode() + "%{json}", url]
        process = subprocess.run(command, capture_output=True, timeout=75)
        if process.returncode:
            raise ValueError("HTTPS fetch failed: " + process.stderr.decode("utf-8", errors="replace")[:2000])
        content, separator, raw_metadata = process.stdout.rpartition(marker)
        if not separator or len(content) > maximum_bytes:
            raise ValueError("Download exceeded its limit or has no transport metadata")
        transport = json.loads(raw_metadata)
        if transport["http_code"] != 200 or transport["url_effective"] != url or transport["ssl_verify_result"] != 0:
            raise ValueError("Unexpected HTTP status, redirect, or TLS validation result")
        headers = headers_path.read_text(encoding="iso-8859-1")
    selected_headers = {}
    for line in headers.splitlines():
        key, colon, value = line.partition(":")
        if colon and key.lower() in {"content-length", "last-modified", "etag", "content-type"}:
            selected_headers[key.lower()] = value.strip()
    return content, {"url": url, "obtained_at_utc": datetime.now(timezone.utc).isoformat(),
                     "size_bytes": len(content), "sha256": hashlib.sha256(content).hexdigest(),
                     "headers": selected_headers, "tls_verification": "enabled; Windows curl/Schannel"}


def download_pilot(directory):
    """Verify publisher links before requesting either of the two dataset files."""
    directory = Path(directory)
    if directory.exists():
        raise ValueError("Choose a new directory; existing acquisitions are never overwritten")
    evidence = []
    metadata = {}
    for name, url in (("release_index", ROOT), ("scenario_index", BASE),
                      ("labels_index", BASE + "bro/"), ("scenario_readme", BASE + "README.md")):
        data, info = _fetch(url, 200_000)
        metadata[name] = data.decode("utf-8")
        evidence.append({"kind": name, **info})
    if ("IndividualScenarios/" not in metadata["release_index"]
            or PCAP_NAME not in metadata["scenario_index"]
            or 'href="bro/"' not in metadata["scenario_index"]
            or "conn.log.labeled" not in metadata["labels_index"]
            or "CTU-IoT-Malware-Capture-20" not in metadata["scenario_readme"]
            or "192.168.100.103" not in metadata["scenario_readme"]):
        raise ValueError("Official scenario/version association could not be verified")
    pcap, pcap_info = _fetch(PCAP_URL, 5_000_000)
    labels, label_info = _fetch(LABEL_URL, 1_000_000)
    if pcap[:4] not in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}:
        raise ValueError("The published PCAP is not a recognized capture")
    if b"#fields" not in labels or b"detailed-label" not in labels:
        raise ValueError("The published reference is not a labeled Zeek log")
    manifest = {
        "manifest_version": "sipymes.iot23.sources.v1", "scenario": SCENARIO,
        "dataset_release": "IoT-23 v1 (publisher release 1.0.0); official IndividualScenarios snapshot",
        "release_citation": "https://zenodo.org/records/4743746",
        "pair_verification": "Both files linked under the same official v1 scenario directory; README confirms scenario, date and host",
        "archive_byte_identity": "Not verified against the full Zenodo archive; archive intentionally not downloaded",
        "metadata_evidence": evidence,
        "files": [{"role": "pcap", "local_name": PCAP_NAME, **pcap_info},
                  {"role": "labels", "local_name": "conn.log.labeled", **label_info}],
    }
    directory.mkdir(parents=True)
    for name, data in ((PCAP_NAME, pcap), ("conn.log.labeled", labels)):
        with (directory / name).open("xb") as output:
            output.write(data)
    with (directory / "provenance.json").open("x", encoding="utf-8") as output:
        json.dump(manifest, output, indent=2, ensure_ascii=False)
    return manifest


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Fetch only the small official IoT-23 scenario 20-1 pair")
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    acquired = download_pilot(args.directory)
    print(json.dumps({"scenario": acquired["scenario"], "files": acquired["files"]}, indent=2))
