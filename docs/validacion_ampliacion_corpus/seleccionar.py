"""Publisher metadata only; never request PCAP/log bodies or held-out sources."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from seguridad_pymes.iot23_sources import _fetch

OUTPUT = Path(__file__).resolve().parent
BASE = "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/"
UNUSED_IDS = (1, 3, 7, 9, 17, 21, 33, 35, 36, 39, 42, 43, 44, 48, 49, 52, 60)
RESERVED = ("CTU-IoT-Malware-Capture-34-1", "CTU-Honeypot-Capture-5-1")


def head(url):
    command = ["curl.exe", "--head", "--fail", "--silent", "--show-error", "--proto", "=https", "--max-time", "30", url]
    result = subprocess.run(command, check=True, capture_output=True, timeout=40)
    text = result.stdout.decode("iso-8859-1")
    headers = {k.lower(): v.strip() for line in text.splitlines() for k, colon, v in [line.partition(":")] if colon}
    if "200 OK" not in text or "content-length" not in headers:
        raise ValueError("No verified HEAD size")
    return {"url": url, "checked_at_utc": datetime.now(timezone.utc).isoformat(),
            "size_bytes": int(headers["content-length"]), "headers": headers, "raw_headers": text}


def main():
    scenarios = [f"CTU-IoT-Malware-Capture-{n}-1" for n in UNUSED_IDS] + ["CTU-Honeypot-Capture-7-1"]
    records = []
    for scenario in scenarios:
        assert scenario not in RESERVED
        content, transport = _fetch(BASE + scenario + "/", 200_000)
        text = content.decode("utf-8")
        lines = [line for line in text.splitlines() if ".pcap" in line or "Somfy-" in line]
        record = {"scenario": scenario, "index": {**transport, "text": text}, "published_file_rows": lines}
        if scenario in {"CTU-IoT-Malware-Capture-3-1", "CTU-IoT-Malware-Capture-42-1", "CTU-IoT-Malware-Capture-21-1"}:
            readme, meta = _fetch(BASE + scenario + "/README.md", 200_000)
            record["readme"] = {**meta, "text": readme.decode("utf-8")}
            bro, meta = _fetch(BASE + scenario + "/bro/", 200_000)
            bro_text = bro.decode("utf-8")
            if 'href="conn.log.labeled"' not in bro_text:
                raise ValueError("Official paired labels link absent")
            record["labels_index"] = {**meta, "text": bro_text}
            captures = re.findall(r'href="([^"/]+\.pcap)"', text)
            captures = [x for x in captures if x not in {"test.pcap", "telnet.pcap"} and "only5000" not in x]
            if len(captures) != 1:
                raise ValueError("Expected one full official capture")
            record["files_head"] = [head(BASE + scenario + "/" + captures[0]), head(BASE + scenario + "/bro/conn.log.labeled")]
        records.append(record)
        print(scenario, " | ".join(re.sub("<[^>]+>", " ", x).strip() for x in lines), flush=True)
    report = {"checked_at_utc": datetime.now(timezone.utc).isoformat(), "metadata_only": True,
        "reserved_not_requested": list(RESERVED), "scenarios": records,
        "official_labels_summary": {"source": "https://www.stratosphereips.org/datasets-iot23",
            "3-1": {"Attack": 5962, "Benign": 4536, "C&C": 8, "PartOfAHorizontalPortScan": 145597},
            "42-1": {"Benign": 4420, "C&C-FileDownload": 3, "FileDownload": 3},
            "21-1": {"Benign": 3272, "C&C-Torii": 14}},
        "warning": "Published reference counts and detailed labels do not establish extractor flow counts, admitted coverage, TCP bidirectionality or independent attacks"}
    with (OUTPUT / "seleccion_fuentes.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
