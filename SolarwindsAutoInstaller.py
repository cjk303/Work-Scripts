#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SolarWinds Agent Bootstrapper — ALWAYS patches OEM installer.

Features:
  - DNS preflight for Orion + pollers (FQDN + short); auto-fix /etc/hosts in --auto or prompt interactively
  - Fetch OEM installer (relaxed validation) with Orion IP priority
  - Probe & download agent package (Ubuntu fallback 22.04→20.04; RHEL majors 10/9/8/7) to /tmp/swiagent.pkg
  - ALWAYS patch OEM script to:
      * set OS/DISTRO/VERSION/ARCH + AUTO_SHELL='/bin/sh'
      * set URL='https://orion.epiqcorp.com', PACKAGE_PATH, FALLBACK_PACKAGE_URL
      * override download_package() to use INSTALL_PACKAGE or hardened fetch
      * fix ${PACKAGE} to ${INSTALL_PACKAGE}, and inject CURL/WGET opts
  - Run patched OEM installer with INSTALL_PACKAGE (offline install)
  - AWX JSON mode, diagnostics, --auto/--verbose/--keep-temp

Requires Python 3.6+.
"""

import os
import sys
import random
import subprocess
import platform
import re
import shutil
import glob
import time
import socket
import json
import argparse
import xml.etree.ElementTree as ET
from typing import Optional, Tuple, List, Dict
from urllib.parse import urlsplit

# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------
ORION_BASE_URL = "https://orion.epiqcorp.com"
ORION_BASE_IP  = "10.35.20.100"  # BigIP IP for Python fetches (verify=False)
SWI_CFG_PATH   = "/opt/SolarWinds/Agent/bin/swiagent.cfg"

# Engines per DC: (FQDN hostname, IP, requestId)
DATA = {
    "LVDC": {
        "engines": [
            ("p054slwapps03.epiqcorp.com", "10.35.15.53",  "d90025c0-114d-4100-a4ba-9e21c32212e5"),
            ("p054slwapps04.epiqcorp.com", "10.35.15.54",  "9301943e-47fd-4c79-b060-7948fe80fed1"),
            ("p054slwapps05.epiqcorp.com", "10.35.15.120", "484a2ded-3fd7-4fe1-9f4d-0992bbc94a1a"),
            ("p054slwapps06.epiqcorp.com", "10.35.15.56",  "88c3a4fd-8565-4b10-8c4b-7ad09b6f1a6d"),
            ("p054slwapps07.epiqcorp.com", "10.35.15.57",  "1efeb8eb-3048-4edc-ba0a-b0f2a956f990"),
            ("p054slwapps08.epiqcorp.com", "10.35.15.58",  "634a5cac-7c8b-47a4-9e96-06af27f3bf03"),
            ("p054slwapps09.epiqcorp.com", "10.35.15.59",  "e1424c4c-c913-469a-8115-6794bfba0641"),
            ("p054slwapps10.epiqcorp.com", "10.35.15.60",  "4b31b30d-9f48-4825-ba79-af675115cb08"),
        ],
    },
    "TUDC": {
        "engines": [
            ("sea-swsam-01.epiqcorp.com", "10.67.212.77",  "e607e061-4c83-4abd-80a6-79140d077405"),
            ("sea-swsam-02.epiqcorp.com", "10.67.212.102", "ab9f6aa3-54c7-482a-a290-7b320c3b8df1"),
        ],
    },
    "HKDC": {
        "engines": [
            ("p062slwapps15.epiqcorp.com", "10.163.15.15", "816bf7cd-1afa-4c35-b9ff-64bc23cbebb8"),
            ("p062slwapps22.epiqcorp.com", "10.163.15.19", "adfd2ef1-90eb-465e-a227-0191fcf644a3"),
        ],
    },
    "UKDC": {
        "engines": [
            ("p064slwapps14.epiqcorp.com", "10.100.15.14", "585e17a6-8dc6-4bfb-bd5e-346796743885"),
            ("p064slwapps13.epiqcorp.com", "10.100.15.10", "79c34464-25e7-4ffb-8a84-cb94406cf35e"),
        ],
    },
    "DEDC": {
        "engines": [
            ("p063slwapps20.epiqcorp.com", "10.104.15.14", "4c6d7c38-c801-42c4-b499-ead1a01fa0dc"),
        ],
    },
    "MEDC": {
        "engines": [
            ("aus-c-itu-44.epiqcorp.com", "10.153.120.124", "0d693161-08be-4ac3-aa08-140fe0e7817e"),
        ],
    },
    "KADC": {
        "engines": [
            ("p082slwapps19.epiqcorp.com", "10.106.68.19", "d3514259-7245-435d-8ce6-41519cd589c6"),
        ],
    },
}

# Hostname → DC guess mapping (substring-based)
HOSTNAME_DC_MAP = {
    "054": "LVDC",
    "082": "KADC",
    "053": "HKDC",
    "062": "HKDC",
    "064": "UKDC",
    "063": "DEDC",
    "078": "DEDC",
    "076": "MEDC",
    "061": "TUDC",
    "077": "TUDC",
}

# ---------------------------------------------------------
# Output / colors
# ---------------------------------------------------------
AWX_MODE = False

def _use_color() -> bool:
    return (not AWX_MODE) and sys.stdout.isatty() and os.environ.get("NO_COLOR", "") == ""

def colorize(text, color):
    return f"\033[{color}m{text}\033[0m" if _use_color() else text

def info(msg):
    if not AWX_MODE: print(colorize(f"[INFO] {msg}", "36"))
def ok(msg):
    if not AWX_MODE: print(colorize(f"[OK] {msg}", "32"))
def warn(msg):
    if not AWX_MODE: print(colorize(f"[WARN] {msg}", "33"))
def error(msg):
    if not AWX_MODE: print(colorize(f"[ERROR] {msg}", "31"))
def hr():
    if not AWX_MODE: print(colorize("-" * 60, "34"))

def awx_output(payload: dict, exit_code: int = 0):
    """Emit JSON for AWX and exit."""
    print(json.dumps(payload))
    sys.exit(exit_code)

# ---------------------------------------------------------
# Dependency bootstrap
# ---------------------------------------------------------
def ensure_dependencies(modules: List[str]):
    missing = []
    for m in modules:
        try:
            __import__(m)
        except Exception:
            missing.append(m)
    if not missing:
        return
    if not AWX_MODE:
        print(f"[INFO] Installing missing Python modules: {', '.join(missing)}")
    py = sys.executable or "python3"
    try:
        for m in missing:
            subprocess.run([py, "-m", "pip", "install", "--quiet", m], check=True)
    except subprocess.CalledProcessError as e:
        if not AWX_MODE:
            print(f"[ERROR] Failed to install dependencies ({', '.join(missing)}). Exit code: {e.returncode}")
            print(f"        Please install them manually, e.g.: {py} -m pip install " + " ".join(missing))
        sys.exit(e.returncode)
    if not AWX_MODE:
        print("[INFO] Dependencies installed. Restarting script...")
    os.execv(py, [py] + sys.argv)

# ---------------------------------------------------------
# OS detection & normalization
# ---------------------------------------------------------
def get_distro_details():
    """Detect distro family (ubuntu/rhel/suse/unknown), ID, version."""
    distro_id = "unknown"
    version_id = "1.0"
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("ID="):
                    distro_id = line.split("=", 1)[1].strip().strip('"').lower()
                elif line.startswith("VERSION_ID="):
                    version_id = line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass

    family = "unknown"
    if "ubuntu" in distro_id or "debian" in distro_id:
        family = "ubuntu"
    elif any(x in distro_id for x in ["rhel", "redhat", "centos", "fedora", "rocky", "alma", "ol"]):
        family = "rhel"
    elif any(x in distro_id for x in ["suse", "sles", "sled"]):
        family = "suse"

    return family, distro_id, version_id

def sw_normalize(family: str, version: str, arch: str):
    """
    Normalize for packageId values:
      - Ubuntu: map newer to nearest supported LTS (22.04 → 22.04 default; we probe/fallback)
      - RHEL:   major only (7/8/9/10)
      - Arch:   x86_64/amd64 -> x64
    """
    fam = "ubuntu" if family == "ubuntu" else "rhel" if family == "rhel" else family

    if fam == "ubuntu":
        try:
            parts = version.split(".")
            vv = f"{int(parts[0])}.{int(parts[1]):02d}" if len(parts) >= 2 else version
        except Exception:
            vv = version
        target = "22.04"
        try:
            maj, minr = [int(x) for x in vv.split(".")[:2]]
            if   (maj, minr) >= (22, 4): target = "22.04"
            elif (maj, minr) >= (20, 4): target = "20.04"
            elif (maj, minr) >= (18, 4): target = "18.04"
            elif (maj, minr) >= (16, 4): target = "16.04"
            else:                        target = "14.04"
        except Exception:
            pass
        version_out = target
    elif fam == "rhel":
        try:
            major = version.split(".")[0]
            mi = int(major) if major.isdigit() else 8
            version_out = "10" if mi >= 10 else "9" if mi >= 9 else "8" if mi >= 8 else "7"
        except Exception:
            version_out = "8"
    else:
        version_out = version or "unknown"

    arch_in = (arch or "").lower()
    arch_out = "x64" if arch_in in ["x86_64", "amd64"] else (arch or "x64")

    return fam, version_out, arch_out

# ---------------------------------------------------------
# DC selection helpers
# ---------------------------------------------------------
def select_engine(dc: str, family: str):
    entry = DATA.get(dc)
    if not entry:
        return None
    if "engines" in entry and isinstance(entry["engines"], list) and entry["engines"]:
        return random.choice(entry["engines"])
    return None

def guess_dc_from_hostname() -> Tuple[Optional[str], str]:
    try:
        hn = socket.gethostname() or platform.node() or ""
    except Exception:
        hn = ""
    hn_l = hn.lower()
    for pattern, dc in HOSTNAME_DC_MAP.items():
        if pattern in hn_l:
            return dc, f"Hostname '{hn}' contains '{pattern}', suggesting {dc}"
    return None, f"Hostname '{hn}' did not match any known DC pattern"

# ---------------------------------------------------------
# DNS helpers & /etc/hosts management
# ---------------------------------------------------------
def host_resolves(host: str) -> bool:
    try:
        socket.gethostbyname(host)
        return True
    except Exception:
        return False

def short_name(fqdn: str) -> str:
    return fqdn.split(".", 1)[0]

def read_hosts() -> str:
    try:
        with open("/etc/hosts", "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""

def write_hosts(entries: Dict[str, str]) -> List[str]:
    """
    Append missing entries; do not duplicate. Returns list of hostnames added.
    Requires root to succeed.
    """
    existing = read_hosts()
    added: List[str] = []
    to_add_lines: List[str] = []
    for host, ip in entries.items():
        pattern = rf'(^|\s){re.escape(host)}(\s|$)'
        if re.search(pattern, existing, flags=re.MULTILINE):
            continue
        to_add_lines.append(f"{ip} {host}")
        added.append(host)
    if not to_add_lines:
        return []
    try:
        with open("/etc/hosts", "a", encoding="utf-8") as f:
            f.write("\n# Added by SolarWinds bootstrapper\n")
            for line in to_add_lines:
                f.write(line + "\n")
        return added
    except PermissionError:
        error("Insufficient permissions to write /etc/hosts (need root).")
        return []
    except Exception as e:
        error(f"Failed to update /etc/hosts: {e}")
        return []

def ensure_dns_for_pollers(dc: str, auto_mode: bool, interactive_tty: bool) -> None:
    """
    Check resolution for Orion FQDN + short, and all pollers FQDN + short in the chosen DC.
    If missing, add to /etc/hosts (auto_mode==True or non-interactive) or prompt (interactive).
    """
    if dc not in DATA or not DATA[dc].get("engines"):
        warn(f"No engines defined for DC '{dc}'. Skipping DNS preflight.")
        return

    desired: Dict[str, str] = {}
    desired["orion.epiqcorp.com"] = ORION_BASE_IP
    desired["orion"]              = ORION_BASE_IP
    for fqdn, ip, _ in DATA[dc]["engines"]:
        desired[fqdn]             = ip
        desired[short_name(fqdn)] = ip

    missing = [h for h in desired.keys() if not host_resolves(h)]
    if not missing:
        ok("DNS preflight: all Orion/poller hostnames (FQDN + short) resolve.")
        return

    warn(f"Missing DNS resolution for: {', '.join(missing)}")
    # Decide whether to add entries
    should_add = False
    if auto_mode or not interactive_tty:
        info("--auto or non-interactive: adding missing entries to /etc/hosts...")
        should_add = True
    else:
        try:
            choice = input("Add missing entries to /etc/hosts? [y/N]: ").strip().lower()
            should_add = (choice in ("y", "yes"))
        except EOFError:
            warn("Non-interactive stdin; will not modify /etc/hosts without --auto.")
            should_add = False

    if not should_add:
        lines = "\n".join(f"{desired[h]} {h}" for h in missing)
        print("\nYou can add them manually with:\n")
        print("sudo tee -a /etc/hosts <<'EOF'")
        print("# SolarWinds pollers (added manually)")
        print(lines)
        print("EOF\n")
        return

    # Attempt to add missing entries
    if os.geteuid() != 0:
        error("Not running as root; cannot modify /etc/hosts. Re-run with sudo or use --auto under sudo.")
        lines = "\n".join(f"{desired[h]} {h}" for h in missing)
        print("\nMissing entries you need to add:\n" + lines + "\n")
        sys.exit(5)

    added = write_hosts({h: desired[h] for h in missing})
    if added:
        ok(f"Added to /etc/hosts: {', '.join(added)}")
    else:
        warn("No entries were added (already present or write failure).")

    # Re-check
    still_missing = [h for h in desired.keys() if not host_resolves(h)]
    if still_missing:
        error(f"Resolution still missing after update: {', '.join(still_missing)}")
        sys.exit(6)
    else:
        ok("DNS preflight: resolution confirmed after /etc/hosts update.")

# ---------------------------------------------------------
# Installer & package download
# ---------------------------------------------------------
def preferred_orion_base_for_python() -> str:
    """
    Base URL for Python fetches:
      - If hostname resolves: https://orion.epiqcorp.com
      - Else:                https://<ORION_BASE_IP>
    Python sets verify=False so cert CN mismatch is tolerated.
    """
    parts = urlsplit(ORION_BASE_URL)
    scheme = parts.scheme or "https"
    host = parts.hostname or "orion.epiqcorp.com"
    if host_resolves(host):
        return f"{scheme}://{host}"
    return f"{scheme}://{ORION_BASE_IP}"

def http_get_to_file(url: str, dest_path: str, requests_module):
    headers = {
        "User-Agent": "curl/8.0 (python-requests) SolarWinds-Agent-Installer",
        "Accept": "*/*",
    }
    r = requests_module.get(url, timeout=60, verify=False, allow_redirects=True, stream=True, headers=headers)
    r.raise_for_status()
    with open(dest_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=1024 * 256):
            if chunk:
                f.write(chunk)
    if os.path.getsize(dest_path) == 0:
        raise RuntimeError(f"Downloaded file is empty: {dest_path}")

def looks_like_oem_shell_script(path: str) -> bool:
    """
    Relaxed validation for OEM installer:
      - Accept if head contains '#!/bin' OR SolarWinds keywords ('SolarWinds' or 'swiagent')
      - Some scripts start with comments/whitespace before the shebang; we still allow them
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(8192)
        if "#!/bin" in head:
            return True
        keywords = ("SolarWinds", "swiagent", "AgentManagement", "DownloadLinux")
        return any(k in head for k in keywords)
    except Exception:
        return False

# ---------------------------------------------------------
# Diagnostics (human + AWX JSON)
# ---------------------------------------------------------
def detect_os_family_version_arch():
    family, distro_id, version_id = get_distro_details()
    arch = platform.machine() or "x86_64"
    return family, distro_id, version_id, arch

def run_diagnostics(awx_json: bool):
    cfg = SWI_CFG_PATH
    if not os.path.exists(cfg):
        msg = f"Config file not found: {cfg}"
        if awx_json:
            awx_output({"status": "error", "message": msg}, exit_code=1)
        error(msg); sys.exit(1)

    try:
        tree = ET.parse(cfg); root = tree.getroot()
    except Exception as e:
        msg = f"Failed to parse {cfg}: {e}"
        if awx_json:
            awx_output({"status": "error", "message": msg}, exit_code=1)
        error(msg); sys.exit(1)

    cert     = root.find("certificate") or ET.Element("certificate")
    execer   = root.find("executer") or ET.Element("executer")
    target   = root.find("target") or ET.Element("target")
    logging  = root.find("logging") or ET.Element("logging")

    device_id   = (execer.findtext("deviceID") or "").strip()
    cert_subj   = (cert.findtext("CertSubject") or "").strip()
    cert_thumb  = (cert.findtext("CertThumbprint") or "").strip()
    pkg_distro  = (execer.findtext("pkg_distro") or "").strip()
    pkg_osver   = (execer.findtext("pkg_osversion") or "").strip()
    pkg_arch    = (execer.findtext("pkg_cpuarch") or "").strip()
    tls_mode    = (execer.findtext("securityProtocolType") or "").strip() or "tls12"
    fips        = (execer.findtext("FipsMode") or "").strip() or "Disabled"
    log_enabled = (logging.findtext("enable") or "").strip().lower() == "true"
    log_level   = (logging.findtext("level") or "").strip() or "INFO"

    host0       = (target.findtext("host0") or "").strip()
    ip0         = (target.findtext("IPAddress0") or "").strip()
    port0       = (target.findtext("port0") or "").strip() or "17778"
    status0     = (target.findtext("status0") or "").strip()

    status_map = {"0": "Unknown/Not initialized", "1": "Connecting", "2": "Connected"}
    status_label = status_map.get(status0, f"Code {status0 or 'N/A'}")

    fam, distro_id, ver_id, arch = detect_os_family_version_arch()
    norm_family, norm_version, norm_arch = sw_normalize(fam, ver_id, arch)
    expected_package_id = f"{norm_family}-{norm_version}-{norm_arch}"
    expected_url = f"{preferred_orion_base_for_python()}/Orion/AgentManagement/DownloadLinuxPackage.ashx?packageId={expected_package_id}"

    if awx_json:
        awx_output({
            "status": "ok",
            "deviceId": device_id,
            "certSubject": cert_subj,
            "certThumbprint": cert_thumb,
            "configPackage": f"{pkg_distro}-{pkg_osver}-{pkg_arch}",
            "expectedPackage": expected_package_id,
            "expectedUrl": expected_url,
            "orionTarget": {"host": host0, "ip": ip0, "port": port0},
            "connection": {"code": status0, "label": status_label},
            "logging": {"enabled": log_enabled, "level": log_level},
            "tls": {"mode": tls_mode, "fips": fips if fips else "Disabled"},
        })

    # Human-readable
    print(colorize("\nSolarWinds Agent Diagnostics", "35"))
    hr()
    print(f"Agent Device ID: {device_id}")
    print(f"Cert Subject:    {cert_subj}")
    print(f"Cert Thumbprint: {cert_thumb}")
    print(f"Package:         {pkg_distro}-{pkg_osver}-{pkg_arch}")
    print(f"TLS Mode:        {tls_mode} | FIPS: {fips}")
    print(f"Orion Target:    {host0} ({ip0}:{port0}) Status: {status0} ({status_label})")
    hr()
    sys.exit(0)

# ---------------------------------------------------------
# Package availability probing
# ---------------------------------------------------------
def resolve_package_variant(family: str, version: str, arch: str, requests_module):
    """
    Probe Orion for available package variants and return the first that responds like a real package.
    """
    base = preferred_orion_base_for_python()

    def uniq(seq):
        out, seen = [], set()
        for x in seq:
            if x not in seen:
                out.append(x); seen.add(x)
        return out

    fam = (family or "").lower()
    ver = (version or "").lower()

    if fam == "ubuntu":
        v = ver
        try:
            parts = v.split(".")
            v = f"{int(parts[0])}.{int(parts[1]):02d}" if len(parts) >= 2 else v
        except Exception:
            pass
        candidates = uniq([v, "22.04", "20.04", "18.04", "16.04", "14.04"])
    elif fam == "rhel":
        v = (ver.split(".")[0] or "8")
        candidates = uniq([v, "10", "9", "8", "7"])
    else:
        return version

    headers = {
        "User-Agent": "curl/8.0 (python-requests) SolarWinds-Agent-Installer",
        "Accept": "*/*",
    }

    for cand in candidates:
        url = f"{base}/Orion/AgentManagement/DownloadLinuxPackage.ashx?packageId={fam}-{cand}-{arch}"
        try:
            r = requests_module.get(url, timeout=20, verify=False, allow_redirects=True, stream=True, headers=headers)
            if r.status_code == 200:
                try:
                    clen = int(r.headers.get("Content-Length", "0"))
                except Exception:
                    clen = 0
                ctype = (r.headers.get("Content-Type", "")).lower()
                if clen > 0 or "application" in ctype or "octet-stream" in ctype:
                    if cand != version:
                        warn(f"Package {fam}-{version}-{arch} not available; using {fam}-{cand}-{arch}.")
                    return cand
        except Exception:
            continue
    return version

# ---------------------------------------------------------
# CLI parsing (NEW: --dc / --datacenter)
# ---------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=os.path.basename(sys.argv[0]),
        description="SolarWinds Agent Bootstrapper"
    )
    p.add_argument(
        "--dc", "--datacenter",
        dest="dc",
        help="Datacenter to use (e.g. LVDC, TUDC, HKDC, UKDC, DEDC, MEDC, KADC). "
             "If specified, the interactive selector is not shown."
    )
    # Preserve legacy positional DC (still works)
    p.add_argument("dc_positional", nargs="?", help="Datacenter (positional). Same as --dc.")

    # Existing flags
    p.add_argument("--awx", action="store_true", help="Emit AWX JSON output")
    p.add_argument("--diagnostics", action="store_true", help="Run diagnostics and exit")
    p.add_argument("--auto", action="store_true", help="Auto-pick DC if possible and auto-fix /etc/hosts")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("--keep-temp", action="store_true", help="Keep temporary files")

    return p

# ---------------------------------------------------------
# Main
# ---------------------------------------------------------
def main():
    global AWX_MODE

    parser = build_arg_parser()
    cli = parser.parse_args()

    AWX_MODE  = cli.awx
    verbose   = cli.verbose
    keep_temp = cli.keep_temp or verbose
    auto_pick = cli.auto

    # Diagnostics short-circuit
    if cli.diagnostics:
        run_diagnostics(awx_json=AWX_MODE)

    # Dependencies for download
    ensure_dependencies(["requests", "urllib3"])
    import requests, urllib3  # noqa: E402
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Choose DC
    suggested_dc, reason = guess_dc_from_hostname()

    # Priority: --dc > positional > old behavior (auto/selector)
    dc = None
    if cli.dc:
        dc = cli.dc.upper()
    elif cli.dc_positional:
        dc = cli.dc_positional.upper()

    if dc:
        # DC explicitly provided: do NOT display selector
        info(f"Datacenter specified: {dc} (selector suppressed)")
    else:
        if auto_pick:
            if suggested_dc:
                info(f"--auto: using suggested DC: {suggested_dc} ({reason})")
                dc = suggested_dc
            else:
                msg = "--auto requested but no suggested DC could be determined from hostname."
                if AWX_MODE:
                    awx_output({"status": "failed", "message": msg}, exit_code=2)
                error(msg)
                parser.print_help()
                sys.exit(2)

        elif sys.stdin.isatty():
            dcs = sorted(DATA.keys())
            print()
            hr(); print(colorize(" SolarWinds Agent Installer - Data Center Selection", "36")); hr()
            default_idx = None
            for idx, dc_name in enumerate(dcs, 1):
                engines = DATA[dc_name].get("engines") or []
                marker = colorize("  ← suggested", "33") if suggested_dc and dc_name == suggested_dc else ""
                if suggested_dc and dc_name == suggested_dc:
                    default_idx = idx
                print(f"  {colorize(str(idx)+'.', '32')} {colorize(dc_name, '35')}  ({len(engines)} engines){marker}")
            print("  q. Quit")
            hr()
            if default_idx:
                prompt = f"Select a data center [1-{len(dcs)} | Enter={default_idx} ({suggested_dc}) | q]: "
            else:
                prompt = f"Select a data center [1-{len(dcs)} or q]: "
            while True:
                choice = input(prompt).strip().lower()
                if choice in ("q", "quit", "exit"):
                    print("Aborted."); sys.exit(0)
                if choice == "" and default_idx:
                    dc = dcs[default_idx - 1]; break
                if choice.isdigit():
                    n = int(choice)
                    if 1 <= n <= len(dcs):
                        dc = dcs[n-1]; break
                print("Please enter a valid number, press Enter to accept the suggestion, or 'q' to quit.")
        else:
            if suggested_dc:
                info(f"No DC argument (non-interactive). Using suggested DC: {suggested_dc} ({reason})")
                dc = suggested_dc
            else:
                if AWX_MODE:
                    awx_output({"status":"failed","message":"No DC provided and no suggestion available"}, exit_code=1)
                parser.print_help()
                sys.exit(1)

    family, distro_id, version_id = get_distro_details()
    arch = platform.machine() or "x86_64"
    info(f"Detected OS: {distro_id.capitalize()} {version_id} (Architecture: {arch})")
    info(f"OS family for installer mapping: {family}")

    if dc not in DATA:
        msg = f"DataCenter '{dc}' not found in config."
        if AWX_MODE:
            awx_output({"status":"failed","message":msg}, exit_code=1)
        error(msg)
        sys.exit(1)

    engine = select_engine(dc, family)
    if not engine:
        msg = f"No engines configured for {dc}."
        if AWX_MODE:
            awx_output({"status":"failed","message":msg}, exit_code=1)
        error(msg); sys.exit(1)

    engine_fqdn, engine_ip, req_id = engine
    info(f"Using Orion Engine: {engine_fqdn} (IP: {engine_ip})")

    # 1) DNS preflight for Orion + pollers (FQDN + short)
    ensure_dns_for_pollers(dc, auto_mode=auto_pick, interactive_tty=sys.stdin.isatty())

    # 2) Download OEM installer (Orion IP first)
    base = preferred_orion_base_for_python()
    installer_urls = [
        f"https://{ORION_BASE_IP}/Orion/AgentManagement/DownloadLinuxOnlineInstallScript.ashx?requestId={req_id}",
        f"{base}/Orion/AgentManagement/DownloadLinuxOnlineInstallScript.ashx?requestId={req_id}",
        f"https://{engine_fqdn}/Orion/AgentManagement/DownloadLinuxOnlineInstallScript.ashx?requestId={req_id}",
        f"http://{engine_fqdn}/Orion/AgentManagement/DownloadLinuxOnlineInstallScript.ashx?requestId={req_id}",
        f"https://{engine_ip}/Orion/AgentManagement/DownloadLinuxOnlineInstallScript.ashx?requestId={req_id}",
        f"http://{engine_ip}/Orion/AgentManagement/DownloadLinuxOnlineInstallScript.ashx?requestId={req_id}",
    ]
    installer_path = "/tmp/oem_installer.sh"
    fetched = False
    for u in installer_urls:
        try:
            info(f"Requesting installer: {u}")
            http_get_to_file(u, installer_path, requests_module=requests)
            if looks_like_oem_shell_script(installer_path):
                size_kb = os.path.getsize(installer_path) // 1024
                head = open(installer_path, "r", encoding="utf-8", errors="ignore").read(4096)
                if "#!/bin" not in head:
                    warn("Installer doesn't start with a shebang, but looks valid. Proceeding.")
                ok(f"Installer received ({size_kb} KB).")
                fetched = True
                break
            else:
                warn("Downloaded content doesn't look like a shell script. Trying next URL...")
        except Exception as e:
            warn(f"Installer fetch failed: {e}")
    if not fetched:
        msg = "Failed to download the OEM installer from all endpoints."
        if AWX_MODE:
            awx_output({"status":"failed","message":msg}, exit_code=1)
        error(msg); sys.exit(1)
    os.chmod(installer_path, 0o755)

    # 3) Decide package variant and download it LOCALLY
    sw_family, sw_version, sw_arch = sw_normalize(family, version_id, arch)
    chosen_version = resolve_package_variant(sw_family, sw_version, sw_arch, requests_module=requests)
    if sw_family == "ubuntu" and chosen_version == "22.04":
        warn("22.04 package may be unavailable; falling back to 20.04.")
        chosen_version = "20.04"
    pkg_id = f"{sw_family}-{chosen_version}-{sw_arch}"
    pkg_url = f"{base}/Orion/AgentManagement/DownloadLinuxPackage.ashx?packageId={pkg_id}"

    pkg_path = "/tmp/swiagent.pkg"
    info(f"Downloading agent package: {pkg_id}")
    try:
        http_get_to_file(pkg_url, pkg_path, requests_module=requests)
    except Exception as e:
        error(f"Failed to download {pkg_id}: {e}")
        sys.exit(10)
    ok(f"Package saved: {pkg_path} ({os.path.getsize(pkg_path)//1024} KB)")

    # 4) ALWAYS patch OEM installer
    info("Patching OEM installer...")
    hr()
    original_script = open(installer_path, "r", encoding="utf-8", errors="ignore").read()

    injected_functions = f"""
identify_distro() {{
    echo "--- Python Patch: Overriding Distro Detection ---"
    OS='linux'
    DISTRO='{sw_family}'
    VERSION='{chosen_version}'
    ARCH='{sw_arch}'

    # Select a download tool
    if command -v curl >/dev/null 2>&1; then
        DT='curl'; CURL_OPTS='-k --fail --location --silent'
    elif command -v wget >/dev/null 2>&1; then
        DT='wget'; WGET_OPTS='--no-check-certificate --quiet'
    else
        echo "ERROR: Neither curl nor wget found. Please install one of them and re-run."
        return 1
    fi

    # Orion base URL and package path (FQDN; cert will match)
    URL='{ORION_BASE_URL}'
    PACKAGE_PATH='/Orion/AgentManagement/DownloadLinuxPackage.ashx?packageId='

    # Ensure the script shell is set for later -c execution
    AUTO_SHELL='/bin/sh'

    # Recompute fallback now that URL is known
    FALLBACK_PACKAGE_URL="${{URL}}${{PACKAGE_PATH}}${{DISTRO}}-${{VERSION}}-${{ARCH}}"

    export OS DISTRO VERSION ARCH DT CURL_OPTS WGET_OPTS URL PACKAGE_PATH AUTO_SHELL FALLBACK_PACKAGE_URL
    return 0
}}

download_package() {{
    # Prefer local package if provided
    if [ -n "$INSTALL_PACKAGE" ] && [ -s "$INSTALL_PACKAGE" ]; then
        echo "Using local package: $INSTALL_PACKAGE"
        return 0
    fi
    PKG_URL="${{URL}}${{PACKAGE_PATH}}${{DISTRO}}-${{VERSION}}-${{ARCH}}"
    OUT="/tmp/swiagent-${{DISTRO}}-${{VERSION}}-${{ARCH}}.pkg"
    echo "Fetching package from: $PKG_URL"
    if [ "$DT" = "curl" ]; then
        if ! curl $CURL_OPTS -o "$OUT" "$PKG_URL"; then
            echo "Download failed via curl."; return 1
        fi
    else
        if ! wget $WGET_OPTS -O "$OUT" "$PKG_URL"; then
            echo "Download failed via wget."; return 1
        fi
    fi
    if [ ! -s "$OUT" ]; then
        echo "Downloaded file is empty."; return 1
    fi
    INSTALL_PACKAGE="$OUT"; export INSTALL_PACKAGE
    echo "Package saved to $OUT and INSTALL_PACKAGE set."
    return 0
}}
"""

    # Rename original functions if present (keep callsites intact)
    for fn in ("identify_distro", "download_package"):
        pattern = rf'^\s*(function\s+)?{fn}\s*\(\)\s*\{{'
        original_script = re.sub(pattern, f'{fn}_ORIG() {{', original_script, flags=re.MULTILINE)

    # Inject after shebang if present
    m = re.match(r'^#!.*\n', original_script)
    idx = m.end() if m else 0
    patched_script = original_script[:idx] + injected_functions + original_script[idx:]

    # Fix ${PACKAGE} bug and inject curl/wget options into raw calls
    patched_script = patched_script.replace('check_package "${PACKAGE}"', 'check_package "${INSTALL_PACKAGE}"')
    patched_script = re.sub(r'(?m)(\bcurl\b)(\s+)', r'curl ${CURL_OPTS}\2', patched_script)
    patched_script = re.sub(r'(?m)(\bwget\b)(\s+)', r'wget ${WGET_OPTS}\2', patched_script)
    patched_script = re.sub(
        r'(?m)^FALLBACK_PACKAGE_URL=.*$',
        f'FALLBACK_PACKAGE_URL=${{URL}}${{PACKAGE_PATH}}{sw_family}-{chosen_version}-{sw_arch}',
        patched_script
    )

    # Save patched script
    local_path = "/tmp/sw_patched_install.sh"
    with open(local_path, "w", encoding="utf-8") as f:
        f.write(patched_script.replace("\r\n", "\n"))
    os.chmod(local_path, 0o755)

    # Execute patched installer with offline package
    info("Executing patched OEM installer (offline package)...")
    hr()
    try:
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        env["INSTALL_PACKAGE"] = pkg_path  # enforce offline usage
        if keep_temp:
            env["KEEP_TMP_DIR"] = "1"
        else:
            env.pop("KEEP_TMP_DIR", None)
        if verbose:
            env["DEBUG"] = "1"
        else:
            env.pop("DEBUG", None)

        # Ensure DT in env
        if shutil.which("curl"):
            env["DT"] = "curl"; env["CURL_OPTS"] = "-k --fail --location --silent"
        elif shutil.which("wget"):
            env["DT"] = "wget"; env["WGET_OPTS"] = "--no-check-certificate --quiet"
        else:
            env["DT"] = ""

        subprocess.run(["/bin/bash", local_path], check=True, env=env)
        hr()
        if AWX_MODE:
            awx_output({
                "status": "installed",
                "dc": dc,
                "engine": engine_fqdn,
                "ip": engine_ip,
                "os": f"{sw_family}-{chosen_version}-{sw_arch}",
            })
        ok("Installation completed successfully.")
    except subprocess.CalledProcessError as e:
        hr()
        rc = e.returncode or 1
        if AWX_MODE:
            awx_output({"status":"failed","code":rc}, exit_code=rc)
        error(f"Patched installer failed with exit code {rc}.")
        # Point to OEM log if present
        candidates = glob.glob("/tmp/swiagent-*/swiagent-install.log")
        if candidates:
            candidates.sort(key=os.path.getmtime, reverse=True)
            info(f"See OEM log: {candidates[0]}")
        sys.exit(rc)
    finally:
        # Clean wrapper
        try:
            if os.path.exists(local_path):
                os.remove(local_path)
        except Exception:
            pass
        # Remove recent OEM temp unless --keep-temp
        if not keep_temp:
            try:
                dirs = sorted(glob.glob("/tmp/swiagent-*"), key=os.path.getmtime, reverse=True)
                if dirs and (time.time() - os.path.getmtime(dirs[0]) < 600):
                    shutil.rmtree(dirs[0], ignore_errors=True)
            except Exception:
                pass

    # Post-check: best-effort service status
    try:
        aid = "/opt/SolarWinds/Agent/bin/swiagentaid.sh"
        if os.path.exists(aid):
            subprocess.run([aid, "status", "swiagentd"], check=False)
        else:
            warn("swiagentaid.sh not found; skipping service status check.")
    except Exception:
        pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        if not AWX_MODE:
            print()
            error("Aborted by user (Ctrl-C).")
        sys.exit(130)  # 128 + SIGINT
