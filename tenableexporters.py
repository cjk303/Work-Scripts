root@p054lnxprom01:/opt/tenable# cat export_assets.py
import os
import time
import json
import gzip
import requests
import sys

BASE_URL = "https://cloud.tenable.com"
CHUNK_SIZE = 1000
POLL_INTERVAL = 5
TIMEOUT = 120

ACCESS_KEY = os.getenv("TIO_ACCESS_KEY")
SECRET_KEY = os.getenv("TIO_SECRET_KEY")

if not ACCESS_KEY or not SECRET_KEY:
    print("ERROR: TIO_ACCESS_KEY / TIO_SECRET_KEY not set", file=sys.stderr)
    sys.exit(1)

HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "X-ApiKeys": f"accessKey={ACCESS_KEY}; secretKey={SECRET_KEY}",
}

def start_export():
    print("[*] Starting asset export")
    r = requests.post(
        f"{BASE_URL}/assets/export",
        headers=HEADERS,
        json={"chunk_size": CHUNK_SIZE},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    export_uuid = r.json()["export_uuid"]
    print(f"[+] Export UUID: {export_uuid}")
    return export_uuid

def wait_for_finish(export_uuid):
    print("[*] Waiting for export to finish")
    while True:
        r = requests.get(
            f"{BASE_URL}/assets/export/{export_uuid}/status",
            headers=HEADERS,
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()

        if data["status"] == "FINISHED":
            chunks = data.get("chunks_available", [])
            print(f"[+] Export finished, chunks: {chunks}")
            return chunks

        time.sleep(POLL_INTERVAL)

def decode_response(resp):
    raw = resp.content
    if not raw:
        return ""

    stripped = raw.lstrip()

    # ✅ If it already looks like JSON, DO NOT gunzip
    if stripped.startswith(b"[") or stripped.startswith(b"{"):
        return raw.decode("utf-8", errors="replace")

    # ✅ Only gunzip if gzip magic bytes exist
    if raw[:2] == b"\x1f\x8b":
        return gzip.decompress(raw).decode("utf-8", errors="replace")

    return raw.decode("utf-8", errors="replace")

def parse_assets(text):
    text = text.lstrip()
    if not text:
        return []

    obj = json.loads(text)

    if isinstance(obj, list):
        return obj

    if isinstance(obj, dict):
        for key in ("assets", "data", "items", "results"):
            if isinstance(obj.get(key), list):
                return obj[key]
        return [obj]

    return []

def download_chunk(export_uuid, chunk_id):
    r = requests.get(
        f"{BASE_URL}/assets/export/{export_uuid}/chunks/{chunk_id}",
        headers=HEADERS,
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    text = decode_response(r)
    return parse_assets(text)

def main():
    export_uuid = start_export()
    chunks = wait_for_finish(export_uuid)

    all_assets = []

    for cid in chunks:
        print(f"[*] Downloading chunk {cid}")
        assets = download_chunk(export_uuid, cid)
        print(f"[+] Chunk {cid}: {len(assets)} assets")
        all_assets.extend(assets)

    with open("all_assets.json", "w") as f:
        json.dump(all_assets, f, indent=2)

    print(f"[✅] Wrote {len(all_assets)} assets to all_assets.json")

if __name__ == "__main__":
    main()
root@p054lnxprom01:/opt/tenable# cat export_vulns.py
#!/usr/bin/env python3
import os
import sys
import time
import json
import codecs
import hashlib
import requests
from typing import Iterable, Set

BASE_URL = "https://cloud.tenable.com"
EXPORT_PATH = "/vulns/export"

# Vulnerability export chunks are based on number of ASSETS per chunk (50..5000).
# On low-RAM hosts, keep this small. Override with env var TIO_NUM_ASSETS.
NUM_ASSETS_PER_CHUNK = int(os.getenv("TIO_NUM_ASSETS", "100"))

POLL_INTERVAL = int(os.getenv("TIO_POLL_INTERVAL", "5"))
TIMEOUT = int(os.getenv("TIO_TIMEOUT", "120"))

OUT_NDJSON = os.getenv("TIO_OUT_NDJSON", "vulnerabilities.ndjson")
STATE_DIR = os.getenv("TIO_STATE_DIR", ".tenable_export_state")
RESUME = os.getenv("TIO_RESUME", "1") != "0"  # default ON

ACCESS_KEY = os.getenv("TIO_ACCESS_KEY")
SECRET_KEY = os.getenv("TIO_SECRET_KEY")

if not ACCESS_KEY or not SECRET_KEY:
    print("ERROR: TIO_ACCESS_KEY / TIO_SECRET_KEY not set", file=sys.stderr)
    sys.exit(1)

HEADERS_JSON = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "X-ApiKeys": f"accessKey={ACCESS_KEY}; secretKey={SECRET_KEY}",
}

# Tenable chunk endpoint returns application/octet-stream with a JSON array body
CHUNK_HEADERS = {
    "Accept": "application/octet-stream",
    "X-ApiKeys": f"accessKey={ACCESS_KEY}; secretKey={SECRET_KEY}",
}


def ensure_state_dir():
    os.makedirs(STATE_DIR, exist_ok=True)


def stable_export_key(payload: dict) -> str:
    """
    Create a stable hash for this export request so we can resume safely.
    """
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def state_file(export_key: str) -> str:
    return os.path.join(STATE_DIR, f"done_chunks_{export_key}.txt")


def load_done_chunks(export_key: str) -> Set[int]:
    path = state_file(export_key)
    done = set()
    if not RESUME:
        return done
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    done.add(int(line))
                except ValueError:
                    pass
    except FileNotFoundError:
        pass
    return done


def mark_chunk_done(export_key: str, chunk_id: int):
    ensure_state_dir()
    path = state_file(export_key)
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{chunk_id}\n")


def start_export() -> (str, str, dict):
    """
    POST /vulns/export
    Uses num_assets (NOT chunk_size). [1](https://docs.tenable.com/web-app-scanning/Content/WAS/Analysis/ExportFindings.htm)[2](https://epiqsystems3-my.sharepoint.com/personal/kamil_olszewski_epiqglobal_com/Documents/Recordings/Tenable%20Reporting-20260317_153347-Meeting%20Recording.mp4?web=1)
    """
    print("[*] Starting vulnerability export")

    payload = {
        "num_assets": NUM_ASSETS_PER_CHUNK,
        "filters": {
            "severity": ["low", "medium", "high", "critical"],
            "state": ["OPEN", "REOPENED"],
        },
    }

    export_key = stable_export_key(payload)

    r = requests.post(
        f"{BASE_URL}{EXPORT_PATH}",
        headers=HEADERS_JSON,
        json=payload,
        timeout=TIMEOUT,
    )

    if r.status_code != 200:
        print("ERROR response from Tenable:")
        print(r.text)
        r.raise_for_status()

    export_uuid = r.json().get("export_uuid")
    if not export_uuid:
        raise RuntimeError(f"No export_uuid returned. Response: {r.text[:500]}")

    print(f"[+] Export UUID: {export_uuid}")
    return export_uuid, export_key, payload


def wait_for_finish(export_uuid: str) -> list:
    """
    GET /vulns/export/{uuid}/status
    Chunks may complete in parallel and may not be sequential. [3](https://pytenable.readthedocs.io/en/stable/api/ot/exports.html)
    """
    print("[*] Waiting for export to finish")
    last_status = None

    while True:
        r = requests.get(
            f"{BASE_URL}{EXPORT_PATH}/{export_uuid}/status",
            headers=HEADERS_JSON,
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()

        status = data.get("status")
        chunks_available = data.get("chunks_available", [])
        total_chunks = data.get("total_chunks")

        if status != last_status:
            print(f"[*] Status: {status} (chunks_available={len(chunks_available)}, total_chunks={total_chunks})")
            last_status = status

        if status == "FINISHED":
            print(f"[+] Export finished, chunks_available: {chunks_available}")
            return chunks_available

        if status in ("ERROR", "FAILED", "CANCELLED"):
            raise RuntimeError(f"Export failed: {data}")

        time.sleep(POLL_INTERVAL)


def iter_text_stream(resp: requests.Response, chunk_bytes: int = 65536) -> Iterable[str]:
    """
    Yield decoded UTF-8 text pieces from a streamed response without loading it all.
    """
    resp.raw.decode_content = True  # urllib3 will decompress if server uses gzip
    decoder = codecs.getincrementaldecoder("utf-8")()
    for b in resp.iter_content(chunk_size=chunk_bytes):
        if not b:
            continue
        yield decoder.decode(b)
    tail = decoder.decode(b"", final=True)
    if tail:
        yield tail


def stream_json_array_chunk_to_ndjson(export_uuid: str, chunk_id: int, out_fh):
    """
    Download a vuln export chunk and stream-convert JSON array -> NDJSON.

    Tenable documents chunk download response body as an array of objects. [4](https://pytenable.readthedocs.io/en/stable/api/cloudsecurity/vulns.html)
    """
    url = f"{BASE_URL}{EXPORT_PATH}/{export_uuid}/chunks/{chunk_id}"
    r = requests.get(url, headers=CHUNK_HEADERS, timeout=TIMEOUT, stream=True)

    if r.status_code != 200:
        print(f"ERROR downloading chunk {chunk_id}:")
        print(r.text)
        r.raise_for_status()

    text_iter = iter_text_stream(r)

    # Build initial buffer until we can detect format
    buf = ""
    first_char = None
    while first_char is None:
        try:
            buf += next(text_iter)
        except StopIteration:
            return
        stripped = buf.lstrip()
        if stripped:
            first_char = stripped[0]

    # Expected: JSON array
    if first_char != "[":
        # Fallback: if it happens to be NDJSON-ish, write each JSON line
        pending = buf
        while True:
            if "\n" in pending:
                line, pending = pending.split("\n", 1)
                line = line.strip()
                if line.startswith("{"):
                    out_fh.write(line + "\n")
                continue
            try:
                pending += next(text_iter)
            except StopIteration:
                line = pending.strip()
                if line.startswith("{"):
                    out_fh.write(line + "\n")
                break
        return

    dec = json.JSONDecoder()

    # Find '[' position after any whitespace
    ws = len(buf) - len(buf.lstrip())
    start_idx = buf.find("[", ws)
    while start_idx == -1:
        try:
            buf += next(text_iter)
        except StopIteration:
            raise RuntimeError("Could not find '[' in chunk stream.")
        ws = len(buf) - len(buf.lstrip())
        start_idx = buf.find("[", ws)

    i = start_idx + 1  # parse after '['

    def need_more() -> bool:
        nonlocal buf
        try:
            buf += next(text_iter)
            return True
        except StopIteration:
            return False

    # Parse objects one-by-one and write NDJSON lines
    while True:
        # Skip whitespace and commas
        while True:
            if i >= len(buf):
                if not need_more():
                    raise RuntimeError("Unexpected EOF while parsing JSON array.")
                continue
            c = buf[i]
            if c in " \t\r\n,":
                i += 1
                continue
            break

        # End of array
        if buf[i] == "]":
            break

        # Decode one JSON object starting at position i
        try:
            obj, end = dec.raw_decode(buf, i)
        except json.JSONDecodeError:
            if not need_more():
                raise
            continue

        out_fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
        i = end

        # Keep memory flat by trimming buffer occasionally
        if i > 2_000_000:
            buf = buf[i:]
            i = 0


def main():
    export_uuid, export_key, payload = start_export()
    chunks = wait_for_finish(export_uuid)

    ensure_state_dir()
    done = load_done_chunks(export_key)

    print(f"[*] Output NDJSON: {OUT_NDJSON}")
    print(f"[*] Resume: {'ON' if RESUME else 'OFF'} (done_chunks={len(done)})")
    print(f"[*] num_assets_per_chunk={NUM_ASSETS_PER_CHUNK}")

    # Append mode if resuming; else overwrite
    mode = "a" if (RESUME and os.path.exists(OUT_NDJSON)) else "w"

    with open(OUT_NDJSON, mode, encoding="utf-8") as f:
        for cid in chunks:
            if cid in done:
                print(f"[*] Skipping chunk {cid} (already done)")
                continue

            print(f"[*] Streaming chunk {cid}")
            stream_json_array_chunk_to_ndjson(export_uuid, cid, f)
            f.flush()
            mark_chunk_done(export_key, cid)
            print(f"[+] Finished chunk {cid}")

    print("[✅] DONE")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user", file=sys.stderr)
        sys.exit(130)
root@p054lnxprom01:/opt/tenable#
