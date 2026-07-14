py
#!/usr/bin/env python3
"""
axonius_tenable_all_locations.py  (v3 — tiered hostname matching)
────────────────────────────────────────────────────────────────
v2 only matched Axonius assets to Tenable vulns via UUID.
Assets without a tenable_uuid appeared as "clean" with 0 vulns,
even if Tenable had hundreds of findings for them.

v3 adds tiered matching from the vuln export's own asset fields:
  1. UUID match    — Axonius tenable_uuid == vuln record asset.uuid
  2. FQDN match    — exact FQDN (case-insensitive)
  3. Short hostname — strip domain from both sides
  4. IP match      — same IPv4 (last resort, unique only)

No extra API calls — the vuln export already contains hostname/fqdn/ip
in every record. We just build an index from it.

Writes TWO CSVs (same as v2):
  1. findings_latest.csv  — one row per finding_id
  2. assets_latest.csv    — one row per asset (rolled-up metrics)

Env vars: same as before (AXONIUS_*, TIO_*).
"""

import json
import os
import re
import sys
import time
import gzip
import csv
import shutil
from collections import defaultdict
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import ssl

# ═════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═════════════════════════════════════════════════════════════════════
AXONIUS_URL    = os.environ.get("AXONIUS_URL", "https://epiq-944551e85e8c358e.on.axonius.com").rstrip("/")
AX_API_KEY     = os.environ.get("AXONIUS_API_KEY", "")
AX_API_SECRET  = os.environ.get("AXONIUS_API_SECRET", "")

TIO_BASE       = os.environ.get("TIO_BASE_URL", "https://cloud.tenable.com")
TIO_ACCESS_KEY = os.environ.get("TIO_ACCESS_KEY", "")
TIO_SECRET_KEY = os.environ.get("TIO_SECRET_KEY", "")
TIO_NUM_ASSETS = int(os.environ.get("TIO_NUM_ASSETS", "100"))
TIO_POLL       = int(os.environ.get("TIO_POLL_INTERVAL", "5"))
TIO_MAX_WAIT   = int(os.environ.get("TIO_MAX_WAIT", "900"))

OUTPUT_DIR     = os.environ.get("OUTPUT_DIR", "/opt/tenable/data")
SNAPSHOT_DATE  = datetime.utcnow().strftime("%Y-%m-%d")
TIMESTAMP      = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
NOW_UTC        = datetime.now(timezone.utc)

SSL_CTX = ssl.create_default_context()

AQL_QUERY = (
    '({{QueryID=62e16cd413b5b0d87afdbdf2}}) '
    'and not ("adapters_data.gui.custom_appliance" == regex("yes", "i")) '
    'and ("specific_data.data.os.type" == "Linux")'
)

# ═════════════════════════════════════════════════════════════════════
# HTTP HELPERS
# ═════════════════════════════════════════════════════════════════════
def http_call(url, method="GET", headers=None, body=None, timeout=120):
    data = json.dumps(body).encode("utf-8") if body else None
    req = Request(url, method=method, data=data, headers=headers or {})
    try:
        with urlopen(req, context=SSL_CTX, timeout=timeout) as resp:
            return resp.read(), resp.status
    except HTTPError as e:
        err = e.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code} {e.reason}: {err[:500]}")

def http_json(url, method="GET", headers=None, body=None, timeout=120):
    raw, _ = http_call(url, method, headers, body, timeout)
    return json.loads(raw)

# ═════════════════════════════════════════════════════════════════════
# PART 1: AXONIUS
# ═════════════════════════════════════════════════════════════════════
def ax_headers():
    return {
        "api-key": AX_API_KEY, "api-secret": AX_API_SECRET,
        "Content-Type": "application/json", "Accept": "application/json",
    }

AX_FIELDS = [
    "specific_data.data.name",
    "specific_data.data.hostname_preferred",
    "specific_data.data.os.type",
    "specific_data.data.os.type_distribution_preferred",
    "specific_data.data.network_interfaces.ips_v4_preferred",
    "specific_data.data.last_seen",
    "adapters",
    "adapters_data.gui.custom_location",
    "adapters_data.gui.custom_appliance",
    "adapters_data.tenable_io_adapter.uuid",
    "adapters_data.tenable_io_adapter.id",
]

def flatten_val(val):
    if val is None:
        return ""
    if isinstance(val, list):
        return ", ".join(str(x) for x in val if x is not None)
    return str(val)

UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)

def extract_uuid(raw_value):
    if not raw_value or not isinstance(raw_value, str):
        return None
    m = UUID_RE.search(raw_value)
    return m.group().lower() if m else None

def get_tenable_uuids(asset):
    uuids = set()
    for key in ["adapters_data.tenable_io_adapter.uuid",
                 "adapters_data.tenable_io_adapter.id"]:
        val = asset.get(key)
        if val is None:
            continue
        if isinstance(val, list):
            for v in val:
                cleaned = extract_uuid(v)
                if cleaned:
                    uuids.add(cleaned)
        elif isinstance(val, str):
            cleaned = extract_uuid(val)
            if cleaned:
                uuids.add(cleaned)
    return uuids

def normalize_location(raw_location):
    loc = flatten_val(raw_location).strip().upper()
    if not loc:
        return "UNKNOWN"
    if "," in loc:
        parts = [p.strip() for p in loc.split(",") if p.strip()]
        loc = parts[0] if parts else "UNKNOWN"
    return loc

def fetch_all_assets():
    print(f"[AX] Fetching with AQL (all locations)...")
    url = f"{AXONIUS_URL}/api/v2/assets/devices"
    all_assets, offset = [], 0
    while True:
        body = {
            "query": AQL_QUERY,
            "fields": AX_FIELDS,
            "include_metadata": True,
            "page": {"offset": offset, "limit": 2000},
        }
        result = http_json(url, "POST", ax_headers(), body, 300)
        assets = result.get("assets", result.get("data", []))
        all_assets.extend(assets)
        total = result.get("meta", {}).get("page", {}).get("totalResources", len(all_assets))
        print(f"    [AX] {len(all_assets)}/{total}")
        if len(all_assets) >= total or not assets:
            break
        offset += 2000
    print(f"[AX] Total: {len(all_assets)} assets")
    return all_assets

# ═════════════════════════════════════════════════════════════════════
# Hostname normalization (shared by Axonius + Tenable sides)
# ═════════════════════════════════════════════════════════════════════
def normalize_short(hostname):
    """Extract short hostname: strip domain, lowercase."""
    if not hostname:
        return ""
    h = hostname.strip().lower()
    dot = h.find(".")
    if dot > 0:
        h = h[:dot]
    return h

def normalize_fqdn(hostname):
    if not hostname:
        return ""
    return hostname.strip().lower()

def normalize_ips(ip_str):
    """Parse an IP field (string, comma-separated, or list-like)."""
    if not ip_str:
        return set()
    if isinstance(ip_str, list):
        ip_str = ", ".join(str(x) for x in ip_str if x)
    ip_str = str(ip_str).strip().strip("[]")
    ips = set()
    for part in re.split(r'[,\s]+', ip_str):
        part = part.strip().strip("'\"")
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', part):
            ips.add(part)
    return ips


def build_lookup(assets):
    """
    Build Axonius lookup structures:
      by_tuuid:  tenable_uuid -> ax_info    (for UUID matching)
      all_ax:    list of (ax_info, tuuids)   (for fallback matching)

    Also builds hostname/IP indexes for fallback matching:
      ax_by_fqdn:  fqdn -> [ax_info, ...]
      ax_by_short: short -> [ax_info, ...]
      ax_by_ip:    ip -> [ax_info, ...]
    """
    by_tuuid = {}
    all_ax = []
    ax_by_fqdn = defaultdict(list)
    ax_by_short = defaultdict(list)
    ax_by_ip = defaultdict(list)
    env_counter = defaultdict(int)

    for a in assets:
        custom_loc = a.get("adapters_data.gui.custom_location")
        custom_appl = a.get("adapters_data.gui.custom_appliance")
        environment = normalize_location(custom_loc)
        env_counter[environment] += 1
        hostname = a.get("specific_data.data.hostname_preferred", "") or ""
        ipv4_raw = flatten_val(a.get("specific_data.data.network_interfaces.ips_v4_preferred"))

        info = {
            "internal_axon_id": a.get("internal_axon_id", ""),
            "environment":      environment,
            "asset_name":       flatten_val(a.get("specific_data.data.name")),
            "hostname":         hostname,
            "os_type":          a.get("specific_data.data.os.type_distribution_preferred", "") or "",
            "os_family":        flatten_val(a.get("specific_data.data.os.type")),
            "ipv4":             ipv4_raw,
            "last_seen":        a.get("specific_data.data.last_seen", "") or "",
            "adapter_count":    a.get("adapter_list_length", 0),
            "adapters":         flatten_val(a.get("adapters", [])),
            "custom_location":  flatten_val(custom_loc),
            "custom_appliance": flatten_val(custom_appl),
            # Normalized fields for matching
            "_fqdn_norm":       normalize_fqdn(hostname),
            "_short_norm":      normalize_short(hostname),
            "_ips":             normalize_ips(ipv4_raw),
        }

        tuuids = get_tenable_uuids(a)
        for tuuid in tuuids:
            by_tuuid[tuuid] = info
        all_ax.append((info, tuuids))

        # Build fallback indexes (only for assets WITHOUT a tenable UUID)
        if not tuuids:
            fqdn = info["_fqdn_norm"]
            if fqdn:
                ax_by_fqdn[fqdn].append(info)
            short = info["_short_norm"]
            if short:
                ax_by_short[short].append(info)
            for ip in info["_ips"]:
                ax_by_ip[ip].append(info)

    print(f"[AX] Tenable UUID mappings: {len(by_tuuid)}")
    print(f"[AX] Fallback indexes: fqdn={len(ax_by_fqdn)} short={len(ax_by_short)} ip={len(ax_by_ip)}")
    for env in sorted(env_counter.keys()):
        print(f"       {env}: {env_counter[env]} assets")
    return by_tuuid, all_ax, ax_by_fqdn, ax_by_short, ax_by_ip


# ═════════════════════════════════════════════════════════════════════
# PART 2: TENABLE — export & parse rich fields
# ═════════════════════════════════════════════════════════════════════
def tio_hdr():
    return {
        "Accept": "application/json", "Content-Type": "application/json",
        "X-ApiKeys": f"accessKey={TIO_ACCESS_KEY}; secretKey={TIO_SECRET_KEY}",
    }

def tio_hdr_chunk():
    return {
        "Accept": "application/octet-stream",
        "X-ApiKeys": f"accessKey={TIO_ACCESS_KEY}; secretKey={TIO_SECRET_KEY}",
    }

def tenable_export():
    print("[TIO] Starting vulnerability export...")
    payload = {
        "num_assets": TIO_NUM_ASSETS,
        "filters": {
            "severity": ["low", "medium", "high", "critical"],
            "state": ["OPEN", "REOPENED"],
        },
    }
    result = http_json(f"{TIO_BASE}/vulns/export", "POST", tio_hdr(), payload, 120)
    export_uuid = result.get("export_uuid")
    if not export_uuid:
        raise RuntimeError(f"No export_uuid: {json.dumps(result)[:300]}")
    print(f"[TIO] Export UUID: {export_uuid}")

    elapsed = 0
    while elapsed < TIO_MAX_WAIT:
        status = http_json(
            f"{TIO_BASE}/vulns/export/{export_uuid}/status",
            "GET", tio_hdr(), timeout=120)
        st = status.get("status")
        chunks = status.get("chunks_available", [])
        if st == "FINISHED":
            print(f"[TIO] Finished, {len(chunks)} chunks")
            return export_uuid, chunks
        if st in ("ERROR", "FAILED", "CANCELLED"):
            raise RuntimeError(f"Export failed: {status}")
        print(f"    [TIO] {st}, {len(chunks)} chunks ready...")
        time.sleep(TIO_POLL)
        elapsed += TIO_POLL
    raise RuntimeError(f"Tenable export timed out after {TIO_MAX_WAIT}s")

def download_chunk(export_uuid, chunk_id):
    raw, _ = http_call(
        f"{TIO_BASE}/vulns/export/{export_uuid}/chunks/{chunk_id}",
        "GET", tio_hdr_chunk(), timeout=120)
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    data = json.loads(text)
    return data if isinstance(data, list) else [data]


SEV_LOOKUP = {"info": 0, "informational": 0, "low": 1,
              "medium": 2, "high": 3, "critical": 4}
SEV_NAME = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def parse_iso(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def extract_finding(v):
    """Extract the fields we care about from one Tenable vuln record."""
    asset = v.get("asset") or {}
    plugin = v.get("plugin") or {}
    vpr = plugin.get("vpr") or {}
    vpr_v2 = plugin.get("vpr_v2") or {}

    auuid = str(asset.get("uuid") or asset.get("id") or v.get("asset_uuid") or "").lower()

    sev = v.get("severity")
    if isinstance(sev, int):
        sev_rank = sev
    elif isinstance(sev, str):
        sev_rank = SEV_LOOKUP.get(sev.lower(), -1)
    else:
        sev_rank = -1

    cves = plugin.get("cve") or []
    if not isinstance(cves, list):
        cves = [str(cves)]
    cve_str = ",".join(str(c) for c in cves if c)

    first_found = parse_iso(v.get("first_found"))
    last_found = parse_iso(v.get("last_found"))
    last_fixed = parse_iso(v.get("last_fixed"))

    age_days = None
    if first_found:
        age_days = int((NOW_UTC - first_found).total_seconds() // 86400)

    return {
        "finding_id":     v.get("finding_id") or "",
        "asset_uuid":     auuid,
        "plugin_id":      str(plugin.get("id") or ""),
        "plugin_name":    plugin.get("name") or "",
        "severity":       SEV_NAME.get(sev_rank, "unknown"),
        "severity_rank":  sev_rank,
        "state":          (v.get("state") or "").upper(),
        "vpr_score":      vpr.get("score"),
        "vpr_v2_score":   vpr_v2.get("score"),
        "cvss3_score":    plugin.get("cvss3_base_score"),
        "epss_score":     plugin.get("epss_score"),
        "on_cisa_kev":    bool(vpr_v2.get("on_cisa_kev", False)),
        "exploit_available":     bool(plugin.get("exploit_available", False)),
        "exploited_by_malware":  bool(plugin.get("exploited_by_malware", False)),
        "in_the_news":    bool(plugin.get("in_the_news", False)),
        "has_patch":      bool(plugin.get("has_patch", False)),
        "unsupported_by_vendor": bool(plugin.get("unsupported_by_vendor", False)),
        "cves":           cve_str,
        "first_found":    first_found.isoformat() if first_found else "",
        "last_found":     last_found.isoformat() if last_found else "",
        "last_fixed":     last_fixed.isoformat() if last_fixed else "",
        "age_days":       age_days if age_days is not None else "",
        "time_taken_to_fix": v.get("time_taken_to_fix") or "",
    }


def extract_tenable_asset_info(v):
    """
    Extract asset identity fields from a vuln record for hostname matching.
    Returns a dict with uuid, hostname, fqdn, ipv4.
    """
    asset = v.get("asset") or {}
    auuid = str(asset.get("uuid") or asset.get("id") or "").lower()
    hostname = asset.get("hostname") or ""
    fqdn = asset.get("fqdn") or ""
    ipv4 = asset.get("ipv4") or ""
    return {
        "uuid": auuid,
        "hostname": hostname,
        "fqdn": fqdn,
        "ipv4": ipv4,
    }


def download_all_findings(export_uuid, chunks):
    """
    Download every chunk, extract findings, dedupe by finding_id.
    Also builds a Tenable asset identity index from the vuln records
    for hostname-based matching.

    Returns:
      findings: dict of finding_id -> finding_dict
      tenable_asset_index: dict of asset_uuid -> {uuid, hostname, fqdn, ipv4}
    """
    print("[TIO] Downloading chunks...")
    findings = {}
    tenable_asset_index = {}  # uuid -> identity info
    total_records = 0

    for i, cid in enumerate(chunks):
        vulns = download_chunk(export_uuid, cid)
        for v in vulns:
            total_records += 1

            # Always collect asset identity (even for non-OPEN findings)
            # so our hostname index is as complete as possible
            asset_info = extract_tenable_asset_info(v)
            if asset_info["uuid"] and asset_info["uuid"] not in tenable_asset_index:
                tenable_asset_index[asset_info["uuid"]] = asset_info

            state = (v.get("state") or "").upper()
            if state not in ("OPEN", "REOPENED"):
                continue
            f = extract_finding(v)
            if not f["finding_id"] or not f["asset_uuid"]:
                continue
            prev = findings.get(f["finding_id"])
            if prev is None or f["severity_rank"] > prev["severity_rank"]:
                findings[f["finding_id"]] = f

        if (i + 1) % 10 == 0:
            print(f"    [TIO] {i+1}/{len(chunks)} chunks, {total_records:,} records, "
                  f"{len(findings):,} findings, {len(tenable_asset_index):,} asset identities")

    print(f"[TIO] {total_records:,} records → {len(findings):,} unique findings")
    print(f"[TIO] {len(tenable_asset_index):,} unique Tenable asset identities collected")
    return findings, tenable_asset_index


# ═════════════════════════════════════════════════════════════════════
# PART 2.5: TIERED MATCHING — match UUID-less Axonius assets to
#           Tenable asset UUIDs via hostname/FQDN/IP
# ═════════════════════════════════════════════════════════════════════
def build_tenable_hostname_indexes(tenable_asset_index):
    """
    Build reverse indexes from the Tenable asset identity data
    collected during the vuln export download.
    """
    by_fqdn = defaultdict(list)
    by_short = defaultdict(list)
    by_ip = defaultdict(list)

    for uuid, info in tenable_asset_index.items():
        # Index by FQDN
        fqdn = normalize_fqdn(info.get("fqdn"))
        if fqdn:
            by_fqdn[fqdn].append(uuid)
        # hostname might also be a FQDN
        hn = normalize_fqdn(info.get("hostname"))
        if hn and hn != fqdn:
            by_fqdn[hn].append(uuid)

        # Index by short hostname
        short = normalize_short(info.get("hostname"))
        if short:
            by_short[short].append(uuid)
        short_fqdn = normalize_short(info.get("fqdn"))
        if short_fqdn and short_fqdn != short:
            by_short[short_fqdn].append(uuid)

        # Index by IP
        ipv4 = (info.get("ipv4") or "").strip()
        if ipv4 and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ipv4):
            by_ip[ipv4].append(uuid)

    # Deduplicate
    by_fqdn = {k: list(set(v)) for k, v in by_fqdn.items()}
    by_short = {k: list(set(v)) for k, v in by_short.items()}
    by_ip = {k: list(set(v)) for k, v in by_ip.items()}

    print(f"[MATCH] Tenable hostname indexes: fqdn={len(by_fqdn)} short={len(by_short)} ip={len(by_ip)}")
    return by_fqdn, by_short, by_ip


def match_unmatched_assets(all_ax, by_tuuid, tenable_asset_index,
                            tio_by_fqdn, tio_by_short, tio_by_ip):
    """
    For Axonius assets that have NO tenable_uuid (or whose UUID didn't
    appear in the vuln export), try to find a matching Tenable asset
    via hostname/FQDN/IP.

    Adds successful matches to by_tuuid so the downstream rollup
    picks them up automatically.

    Returns match stats.
    """
    stats = {"uuid_existing": 0, "fqdn": 0, "short": 0, "ip": 0,
             "ambiguous_short": 0, "ambiguous_ip": 0, "unmatched": 0}

    matched_tenable_uuids = set(by_tuuid.keys())

    for ax_info, tuuids in all_ax:
        # Already matched by UUID?
        if any(t in by_tuuid for t in tuuids):
            stats["uuid_existing"] += 1
            continue

        found_uuid = None
        method = None

        # TIER 2: FQDN match
        fqdn = ax_info.get("_fqdn_norm", "")
        if fqdn:
            candidates = tio_by_fqdn.get(fqdn, [])
            candidates = [c for c in candidates if c not in matched_tenable_uuids]
            if len(candidates) == 1:
                found_uuid = candidates[0]
                method = "fqdn"

        # TIER 3: Short hostname match
        if not found_uuid:
            short = ax_info.get("_short_norm", "")
            if short:
                candidates = tio_by_short.get(short, [])
                candidates = [c for c in candidates if c not in matched_tenable_uuids]
                if len(candidates) == 1:
                    found_uuid = candidates[0]
                    method = "short"
                elif len(candidates) > 1:
                    stats["ambiguous_short"] += 1

        # TIER 4: IP match
        if not found_uuid:
            ax_ips = ax_info.get("_ips", set())
            if ax_ips:
                ip_candidates = set()
                for ip in ax_ips:
                    for c in tio_by_ip.get(ip, []):
                        if c not in matched_tenable_uuids:
                            ip_candidates.add(c)
                if len(ip_candidates) == 1:
                    found_uuid = ip_candidates.pop()
                    method = "ip"
                elif len(ip_candidates) > 1:
                    stats["ambiguous_ip"] += 1

        if found_uuid:
            by_tuuid[found_uuid] = ax_info
            matched_tenable_uuids.add(found_uuid)
            stats[method] += 1
        else:
            stats["unmatched"] += 1

    print(f"[MATCH] Results:")
    print(f"    Already matched (UUID) : {stats['uuid_existing']}")
    print(f"    New matches by FQDN    : {stats['fqdn']}")
    print(f"    New matches by short   : {stats['short']}")
    print(f"    New matches by IP      : {stats['ip']}")
    print(f"    Still unmatched        : {stats['unmatched']}")
    print(f"    Skipped (ambiguous)    : short={stats['ambiguous_short']}  ip={stats['ambiguous_ip']}")
    total_matched = stats['uuid_existing'] + stats['fqdn'] + stats['short'] + stats['ip']
    print(f"    Total matched          : {total_matched}/{total_matched + stats['unmatched']}")
    return stats


# ═════════════════════════════════════════════════════════════════════
# PART 3: ROLL UP PER ASSET
# ═════════════════════════════════════════════════════════════════════
def age_bucket(age_days):
    if age_days is None or age_days == "":
        return "unknown"
    try:
        d = int(age_days)
    except (ValueError, TypeError):
        return "unknown"
    if d <= 7:   return "0_7"
    if d <= 30:  return "8_30"
    if d <= 90:  return "31_90"
    return "over_90"


def rollup_by_asset(findings):
    per_asset = defaultdict(lambda: {
        "total_findings": 0,
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        "vpr_sum": 0.0, "vpr_max": 0.0,
        "epss_sum": 0.0, "epss_max": 0.0,
        "cvss3_max": 0.0,
        "kev_count": 0,
        "exploitable_count": 0,
        "exploit_in_wild_count": 0,
        "critical_exploitable": 0,
        "high_exploitable": 0,
        "fixable_count": 0,
        "unfixable_count": 0,
        "unsupported_count": 0,
        "age_0_7": 0, "age_8_30": 0, "age_31_90": 0, "age_over_90": 0,
        "distinct_cves": set(),
        "last_found_max": None,
    })

    for f in findings.values():
        a = per_asset[f["asset_uuid"]]
        a["total_findings"] += 1
        sev = f["severity"]
        if sev in ("critical", "high", "medium", "low", "info"):
            a[sev] += 1

        vpr = f["vpr_score"]
        if isinstance(vpr, (int, float)):
            a["vpr_sum"] += vpr
            if vpr > a["vpr_max"]:
                a["vpr_max"] = vpr

        epss = f["epss_score"]
        if isinstance(epss, (int, float)):
            a["epss_sum"] += epss
            if epss > a["epss_max"]:
                a["epss_max"] = epss

        cvss = f["cvss3_score"]
        if isinstance(cvss, (int, float)) and cvss > a["cvss3_max"]:
            a["cvss3_max"] = cvss

        if f["on_cisa_kev"]:
            a["kev_count"] += 1
        if f["exploit_available"]:
            a["exploitable_count"] += 1
            if sev == "critical":
                a["critical_exploitable"] += 1
            elif sev == "high":
                a["high_exploitable"] += 1
        if f["exploited_by_malware"] or f["in_the_news"]:
            a["exploit_in_wild_count"] += 1
        if f["has_patch"]:
            a["fixable_count"] += 1
        else:
            a["unfixable_count"] += 1
        if f["unsupported_by_vendor"]:
            a["unsupported_count"] += 1

        bucket = age_bucket(f["age_days"])
        if bucket != "unknown":
            a[f"age_{bucket}"] += 1

        for cve in (f["cves"] or "").split(","):
            cve = cve.strip()
            if cve:
                a["distinct_cves"].add(cve)

        lf = parse_iso(f["last_found"])
        if lf and (a["last_found_max"] is None or lf > a["last_found_max"]):
            a["last_found_max"] = lf

    for uuid, a in per_asset.items():
        a["distinct_cve_count"] = len(a["distinct_cves"])
        del a["distinct_cves"]
        a["last_found_max"] = a["last_found_max"].isoformat() if a["last_found_max"] else ""
        a["vpr_sum"] = round(a["vpr_sum"], 2)
        a["vpr_max"] = round(a["vpr_max"], 2)
        a["epss_sum"] = round(a["epss_sum"], 4)
        a["epss_max"] = round(a["epss_max"], 4)
        a["cvss3_max"] = round(a["cvss3_max"], 2)

    return per_asset


# ═════════════════════════════════════════════════════════════════════
# PART 4: WRITE CSVs
# ═════════════════════════════════════════════════════════════════════
FINDINGS_COLUMNS = [
    "snapshot_date", "finding_id", "asset_uuid", "plugin_id", "plugin_name",
    "severity", "severity_rank", "state",
    "vpr_score", "vpr_v2_score", "cvss3_score", "epss_score",
    "on_cisa_kev", "exploit_available", "exploited_by_malware", "in_the_news",
    "has_patch", "unsupported_by_vendor",
    "cves", "first_found", "last_found", "last_fixed",
    "age_days", "time_taken_to_fix",
]

ASSET_COLUMNS = [
    "snapshot_date", "environment", "internal_axon_id", "tenable_uuid",
    "hostname", "asset_name", "os_type", "os_family", "ipv4",
    "custom_location", "custom_appliance", "last_seen",
    "adapter_count", "adapters",
    "total_cve", "critical_cve", "high_cve", "medium_cve", "low_cve", "info_cve",
    "distinct_cve_count",
    "vpr_sum", "vpr_max",
    "epss_sum", "epss_max",
    "cvss3_max",
    "kev_count",
    "exploitable_count", "exploit_in_wild_count",
    "critical_exploitable", "high_exploitable",
    "fixable_count", "unfixable_count", "unsupported_count",
    "age_0_7", "age_8_30", "age_31_90", "age_over_90",
    "tenable_last_found", "scan_age_days",
    "join_method",
]


def write_findings_csv(findings, path):
    print(f"[*] Writing findings CSV: {path}")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FINDINGS_COLUMNS, extrasaction="ignore")
        w.writeheader()
        for finding in findings.values():
            row = {"snapshot_date": SNAPSHOT_DATE, **finding}
            w.writerow(row)
    print(f"[+] {len(findings):,} findings written")


def build_and_write_assets_csv(by_tuuid, all_ax, asset_rollups, match_stats, path):
    print(f"[*] Writing assets CSV: {path}")
    rows = []
    seen = set()

    # First pass: assets with Tenable matches (UUID or hostname-matched)
    for tuuid, rollup in asset_rollups.items():
        ax = by_tuuid.get(tuuid)
        if not ax or ax["internal_axon_id"] in seen:
            continue
        seen.add(ax["internal_axon_id"])

        lfm = rollup["last_found_max"]
        scan_age = ""
        if lfm:
            lf_dt = parse_iso(lfm)
            if lf_dt:
                scan_age = int((NOW_UTC - lf_dt).total_seconds() // 86400)

        rows.append({
            "snapshot_date": SNAPSHOT_DATE,
            **{k: v for k, v in ax.items() if not k.startswith("_")},  # skip _norm fields
            "tenable_uuid": tuuid,
            "total_cve":    rollup["total_findings"],
            "critical_cve": rollup["critical"],
            "high_cve":     rollup["high"],
            "medium_cve":   rollup["medium"],
            "low_cve":      rollup["low"],
            "info_cve":     rollup["info"],
            "distinct_cve_count":   rollup["distinct_cve_count"],
            "vpr_sum":              rollup["vpr_sum"],
            "vpr_max":              rollup["vpr_max"],
            "epss_sum":             rollup["epss_sum"],
            "epss_max":             rollup["epss_max"],
            "cvss3_max":            rollup["cvss3_max"],
            "kev_count":            rollup["kev_count"],
            "exploitable_count":    rollup["exploitable_count"],
            "exploit_in_wild_count": rollup["exploit_in_wild_count"],
            "critical_exploitable": rollup["critical_exploitable"],
            "high_exploitable":     rollup["high_exploitable"],
            "fixable_count":        rollup["fixable_count"],
            "unfixable_count":      rollup["unfixable_count"],
            "unsupported_count":    rollup["unsupported_count"],
            "age_0_7":     rollup["age_0_7"],
            "age_8_30":    rollup["age_8_30"],
            "age_31_90":   rollup["age_31_90"],
            "age_over_90": rollup["age_over_90"],
            "tenable_last_found": rollup["last_found_max"],
            "scan_age_days":      scan_age,
            "join_method":        "uuid_match",
        })

    # Second pass: clean assets (no match at all)
    zero = {col: 0 for col in [
        "total_cve", "critical_cve", "high_cve", "medium_cve", "low_cve", "info_cve",
        "distinct_cve_count", "kev_count",
        "exploitable_count", "exploit_in_wild_count",
        "critical_exploitable", "high_exploitable",
        "fixable_count", "unfixable_count", "unsupported_count",
        "age_0_7", "age_8_30", "age_31_90", "age_over_90",
    ]}
    zero_float = {"vpr_sum": 0.0, "vpr_max": 0.0,
                  "epss_sum": 0.0, "epss_max": 0.0, "cvss3_max": 0.0}

    for ax_info, tuuids in all_ax:
        if ax_info["internal_axon_id"] in seen:
            continue
        seen.add(ax_info["internal_axon_id"])
        rows.append({
            "snapshot_date": SNAPSHOT_DATE,
            **{k: v for k, v in ax_info.items() if not k.startswith("_")},
            "tenable_uuid": next(iter(tuuids), ""),
            **zero, **zero_float,
            "tenable_last_found": "",
            "scan_age_days": "",
            "join_method": "clean_asset",
        })

    rows.sort(key=lambda r: (r["environment"], r["hostname"]))

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=ASSET_COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    matched_count = sum(1 for r in rows if r["join_method"] == "uuid_match")
    clean_count = sum(1 for r in rows if r["join_method"] == "clean_asset")
    print(f"[+] {len(rows):,} assets written  (matched={matched_count}, clean={clean_count})")
    return rows


# ═════════════════════════════════════════════════════════════════════
# SUMMARY
# ═════════════════════════════════════════════════════════════════════
def print_summary(rows, match_stats):
    by_env = defaultdict(lambda: {
        "count": 0, "critical": 0, "high": 0, "kev": 0,
        "exploitable_crit": 0, "vpr_sum": 0.0,
    })
    for r in rows:
        e = r["environment"]
        by_env[e]["count"] += 1
        by_env[e]["critical"] += r["critical_cve"]
        by_env[e]["high"] += r["high_cve"]
        by_env[e]["kev"] += r["kev_count"]
        by_env[e]["exploitable_crit"] += r["critical_exploitable"]
        by_env[e]["vpr_sum"] += r["vpr_sum"] or 0

    print(f"\n{'═' * 84}")
    print(f"  BY ENVIRONMENT — {SNAPSHOT_DATE}")
    print(f"{'═' * 84}")
    print(f"  {'Env':<10} {'Assets':>8} {'Crit':>8} {'High':>8} {'KEV':>6} {'ExpCrit':>8} {'VPR Σ':>10}")
    print(f"  {'─' * 70}")
    grand = {"count": 0, "critical": 0, "high": 0, "kev": 0,
             "exploitable_crit": 0, "vpr_sum": 0.0}
    for env in sorted(by_env.keys()):
        d = by_env[env]
        print(f"  {env:<10} {d['count']:>8} {d['critical']:>8} {d['high']:>8} "
              f"{d['kev']:>6} {d['exploitable_crit']:>8} {d['vpr_sum']:>10.1f}")
        for k in grand:
            grand[k] += d[k]
    print(f"  {'─' * 70}")
    print(f"  {'TOTAL':<10} {grand['count']:>8} {grand['critical']:>8} {grand['high']:>8} "
          f"{grand['kev']:>6} {grand['exploitable_crit']:>8} {grand['vpr_sum']:>10.1f}")
    print(f"{'═' * 84}")

    print(f"\n  Match breakdown:")
    print(f"    UUID (from Axonius adapter) : {match_stats.get('uuid_existing', 0)}")
    print(f"    FQDN hostname match         : {match_stats.get('fqdn', 0)}")
    print(f"    Short hostname match         : {match_stats.get('short', 0)}")
    print(f"    IP match                     : {match_stats.get('ip', 0)}")
    print(f"    Unmatched (truly clean)      : {match_stats.get('unmatched', 0)}")
    print(f"    Ambiguous (skipped)          : short={match_stats.get('ambiguous_short', 0)} ip={match_stats.get('ambiguous_ip', 0)}")


# ═════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════
def main():
    missing = []
    if not AX_API_KEY:     missing.append("AXONIUS_API_KEY")
    if not AX_API_SECRET:  missing.append("AXONIUS_API_SECRET")
    if not TIO_ACCESS_KEY: missing.append("TIO_ACCESS_KEY")
    if not TIO_SECRET_KEY: missing.append("TIO_SECRET_KEY")
    if missing:
        print(f"ERROR: Missing env vars: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    assets_latest   = os.path.join(OUTPUT_DIR, "assets_latest.csv")
    findings_latest = os.path.join(OUTPUT_DIR, "findings_latest.csv")
    assets_arch     = os.path.join(OUTPUT_DIR, f"assets_{TIMESTAMP}.csv")
    findings_arch   = os.path.join(OUTPUT_DIR, f"findings_{TIMESTAMP}.csv")

    print(f"[*] Pipeline v3 started @ {TIMESTAMP}")
    print(f"[*] Output: {OUTPUT_DIR}")

    # Step 1: Axonius — fetch all Linux assets
    assets = fetch_all_assets()
    by_tuuid, all_ax, ax_by_fqdn, ax_by_short, ax_by_ip = build_lookup(assets)
    if not all_ax:
        print("ERROR: No assets returned", file=sys.stderr)
        sys.exit(1)

    # Step 2: Tenable — vuln export (also collects asset identities)
    export_uuid, chunks = tenable_export()
    findings, tenable_asset_index = download_all_findings(export_uuid, chunks)

    # Step 3: Hostname matching — match UUID-less Axonius assets
    tio_by_fqdn, tio_by_short, tio_by_ip = build_tenable_hostname_indexes(tenable_asset_index)
    match_stats = match_unmatched_assets(
        all_ax, by_tuuid, tenable_asset_index,
        tio_by_fqdn, tio_by_short, tio_by_ip)

    # Step 4: Save findings CSV
    write_findings_csv(findings, findings_latest)
    shutil.copy2(findings_latest, findings_arch)

    # Step 5: Roll up per asset (now includes hostname-matched assets)
    asset_rollups = rollup_by_asset(findings)

    # Step 6: Write asset-level CSV
    rows = build_and_write_assets_csv(by_tuuid, all_ax, asset_rollups, match_stats, assets_latest)
    shutil.copy2(assets_latest, assets_arch)

    print(f"\n[+] Findings CSV: {findings_latest}")
    print(f"[+] Assets CSV:   {assets_latest}")
    print(f"[+] Archives:     {findings_arch} / {assets_arch}")

    print_summary(rows, match_stats)
    print(f"\n[✅] Done @ {datetime.utcnow().strftime('%H:%M:%S')} UTC")


if __name__ == "__main__":
    main()
