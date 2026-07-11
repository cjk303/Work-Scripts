
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VMware VM Snapshot Creator (refactored with TLS fallback)
---------------------------------------------------------
Goals of this refactor:
- Preserve original CLI and behavior (backward compatible).
- Reduce load on vCenter/vSphere by using PropertyCollector batched retrieval.
- Ensure views are destroyed and sessions are disconnected in all code paths.
- Keep single-threaded default; multithreading only spans vCenters (when enabled).
- Thread-safe cache updates; avoid racing when multithreaded across vCenters.
- Auto-fallback to unverified TLS if certificate verification fails.
"""

import ssl
import time
import argparse
import os
import json
import threading
from typing import List, Dict, Optional, Callable, Tuple

from cryptography.fernet import Fernet
from concurrent.futures import ThreadPoolExecutor, as_completed

from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim, vmodl

# -------------------- GLOBALS & LOCKS --------------------
cache_lock = threading.Lock()        # prevents multiple full-cache rebuilds
cache_write_lock = threading.Lock()  # protects concurrent cache updates

# -------------------- SSL HELPERS --------------------
def build_ssl_context(no_verify: bool) -> ssl.SSLContext:
    """Secure-by-default; opt-out with --no-verify."""
    if no_verify:
        return ssl._create_unverified_context()
    ctx = ssl.create_default_context()
    return ctx

def build_unverified_context() -> ssl.SSLContext:
    """Explicit helper used by fallback on cert verification failure."""
    return ssl._create_unverified_context()

# ---------------------------------------------------------
# -------------------- CREDENTIALS ------------------------
# ---------------------------------------------------------
def load_encrypted_credentials(cred_file: str, key_file: str) -> List[Dict]:
    if not os.path.exists(cred_file):
        raise FileNotFoundError(f"Credentials file '{cred_file}' not found.")
    if not os.path.exists(key_file):
        raise FileNotFoundError(f"Key file '{key_file}' not found.")

    with open(key_file, "rb") as f:
        key = f.read()
    fernet = Fernet(key)

    vcenters: List[Dict] = []
    with open(cred_file, "rb") as f:
        for enc_line in f:
            enc_line = enc_line.strip()
            if not enc_line:
                continue
            line = fernet.decrypt(enc_line).decode()
            parts = line.split(",")
            if len(parts) != 3:
                raise ValueError(f"Invalid decrypted line: {line}")
            host, user, password = parts
            vcenters.append({"host": host.strip(), "user": user.strip(), "password": password.strip()})
    return vcenters

# ---------------------------------------------------------
# ------------------------ CACHE --------------------------
# ---------------------------------------------------------
def load_cache(cache_file: str, key_file: str) -> Dict:
    if not os.path.exists(cache_file) or not os.path.exists(key_file):
        return {}
    with open(key_file, "rb") as f:
        key = f.read()
    fernet = Fernet(key)
    with open(cache_file, "rb") as f:
        encrypted = f.read()
    try:
        decrypted = fernet.decrypt(encrypted)
        return json.loads(decrypted)
    except Exception:
        return {}

def save_cache(cache: Dict, cache_file: str, key_file: str):
    with open(key_file, "rb") as f:
        key = f.read()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(cache).encode())
    with open(cache_file, "wb") as f:
        f.write(encrypted)

# ---------------------------------------------------------
# -------------- VCENTER CONNECT / UTILITIES --------------
# ---------------------------------------------------------
def connect_to_vcenter(host: str, user: str, password: str,
                       ssl_context: ssl.SSLContext,
                       no_verify_flag: bool,
                       verbose: bool = False,
                       progress_callback: Optional[Callable[[str], None]] = None) -> Tuple[object, bool]:
    """
    Try verified TLS first; if a certificate verification error occurs and
    --no-verify was NOT specified, retry with unverified TLS.

    Returns: (ServiceInstance, used_unverified_tls: bool)
    """
    if verbose and progress_callback:
        progress_callback(f"Connecting to vCenter {host}...")

    # Attempt with provided (likely verified) context
    try:
        si = SmartConnect(host=host, user=user, pwd=password, sslContext=ssl_context)
        if verbose and progress_callback:
            progress_callback(f"Connected to {host} (verified TLS)")
        return si, False
    except Exception as e:
        msg = str(e)
        cert_errors = (
            "CERTIFICATE_VERIFY_FAILED",
            "certificate verify failed",
            "unable to get local issuer certificate",
            "hostname mismatch",
        )

        # If caller already asked for no-verify, don't fallback—just report the failure.
        if no_verify_flag:
            raise ConnectionError(f"Failed to connect to {host}: {e}")

        # Auto-fallback only for certificate-related failures
        if any(s in msg for s in cert_errors):
            if verbose and progress_callback:
                progress_callback(f"TLS verification failed for {host}: {e}. Retrying without verification...")
            try:
                si = SmartConnect(host=host, user=user, pwd=password, sslContext=build_unverified_context())
                if verbose and progress_callback:
                    progress_callback(f"Connected to {host} (UNVERIFIED TLS FALLBACK)")
                return si, True
            except Exception as e2:
                raise ConnectionError(f"Failed to connect to {host} even after fallback: {e2}") from e

        # Non-certificate error: raise immediately
        raise ConnectionError(f"Failed to connect to {host}: {e}")

def _collect_vms_properties(content, progress_callback=None, verbose=False):
    """
    Use the PropertyCollector to fetch only the properties we need
    in a single (paginated) request.

    Properties pulled:
      - summary.config.name
      - guest.toolsRunningStatus
      - guest.hostName
      - guest.net (for ipAddress lists)
    """
    view = None
    try:
        view = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.VirtualMachine], True
        )

        traversal_spec = vim.PropertyCollector.TraversalSpec(
            name='tSpec',
            path='view',
            skip=False,
            type=vim.view.ContainerView
        )

        prop_spec = vim.PropertyCollector.PropertySpec(
            type=vim.VirtualMachine,
            all=False,
            pathSet=[
                "summary.config.name",
                "guest.toolsRunningStatus",
                "guest.hostName",
                "guest.net"
            ]
        )

        obj_spec = vim.PropertyCollector.ObjectSpec(
            obj=view,
            selectSet=[traversal_spec],
            skip=False
        )

        filt_spec = vim.PropertyCollector.FilterSpec(
            objectSet=[obj_spec],
            propSet=[prop_spec],
            reportMissingObjectsInResults=False
        )

        pc = content.propertyCollector
        options = vim.PropertyCollector.RetrieveOptions()
        result = pc.RetrievePropertiesEx(specSet=[filt_spec], options=options)

        objects = []
        while True:
            if result and result.objects:
                objects.extend(result.objects)
            if result and result.token:
                result = pc.ContinueRetrievePropertiesEx(token=result.token)
            else:
                break

        if verbose and progress_callback:
            progress_callback(f"Collected properties for {len(objects)} VMs via PropertyCollector.")

        # Normalize into a list of {obj, props}
        vms = []
        for o in objects:
            props = {}
            for dp in o.propSet:
                props[dp.name] = dp.val
            vms.append({"obj": o.obj, "props": props})
        return vms

    finally:
        if view:
            view.Destroy()

def _extract_search_keys(vm_props: Dict) -> Dict:
    """
    Build the searchable keys (lowercased) and a compact vm_data record.
    """
    name = (vm_props.get("summary.config.name") or "").strip()
    name_lower = name.lower()

    tools_state = vm_props.get("guest.toolsRunningStatus")
    host_name = vm_props.get("guest.hostName")
    host_set = set()
    if host_name:
        host_set.add(host_name.strip())

    ip_set = set()
    if tools_state == 'guestToolsRunning':
        guest_net = vm_props.get("guest.net") or []
        for net in guest_net:
            for ip in (getattr(net, "ipAddress", []) or []):
                ip = (ip or "").strip()
                if ip:
                    ip_set.add(ip)

    vm_data = {
        "name": name,
        "ips": sorted(ip_set),
    }

    keys = [name_lower] + [h.lower() for h in host_set] + [ip.lower() for ip in ip_set]
    return {"keys": keys, "vm_data": vm_data}

# ---------------------------------------------------------
# ------------------------ SEARCH -------------------------
# ---------------------------------------------------------
def find_vm_by_ip_or_name(content,
                          vcenter_host: str,
                          search: str,
                          cache: Optional[Dict] = None,
                          skip_cache: bool = False,
                          progress_callback: Optional[Callable[[str], None]] = None,
                          verbose: bool = False) -> Optional[vim.VirtualMachine]:
    """
    vSphere-friendly search:
     1) Optional cache fast-path (per original behavior).
     2) Single PropertyCollector retrieval for all VMs (one batch).
     3) Substring match on VM name; exact match on IP/hostname.
    """
    search_lower = search.lower()

    # Cache fast-path
    target_moid = None
    if cache is not None and not skip_cache:
        cache_key = f"{vcenter_host}::{search_lower}"
        if cache_key in cache:
            if verbose and progress_callback:
                progress_callback(f"VM '{search}' found in cache for {vcenter_host}")
            target_moid = cache[cache_key]["mo_ref"]

    # Single batched retrieval
    vms = _collect_vms_properties(content, progress_callback=progress_callback, verbose=verbose)

    found_obj = None
    for entry in vms:
        vm = entry["obj"]
        props = entry["props"]
        name = (props.get("summary.config.name") or "").lower()

        # Opportunistic cache population (keys: name, hostnames, IPs)
        try:
            extracted = _extract_search_keys(props)
            with cache_write_lock:
                for k in extracted["keys"]:
                    cache_key = f"{vcenter_host}::{k}"
                    cache[cache_key] = {
                        "name": extracted["vm_data"]["name"],
                        "mo_ref": vm._moId,
                        "vcenter": vcenter_host,
                        "ips": extracted["vm_data"]["ips"],
                    }
        except Exception:
            # Cache is best-effort; continue searching
            pass

        # If cache pointed us to a specific moid, prefer that
        if target_moid and getattr(vm, "_moId", None) == target_moid:
            found_obj = vm
            break

        # Matching rules: exact on IP/hostname, substring on name
        extracted = _extract_search_keys(props)
        keys = set(extracted["keys"])
        if (search_lower in name) or (search_lower in keys):
            found_obj = vm
            break

    return found_obj

# ---------------------------------------------------------
# --------------------- SNAPSHOT OPS ----------------------
# ---------------------------------------------------------
def create_snapshot(vm: vim.VirtualMachine, name: str, description: str,
                    memory=False, quiesce=True,
                    progress_callback: Optional[Callable[[str], None]] = None,
                    verbose=False) -> bool:
    if verbose and progress_callback:
        progress_callback(f"Starting snapshot for VM {vm.summary.config.name}")

    # If memory snapshot requested, disable quiesce to avoid conflicts
    effective_quiesce = False if memory else quiesce
    if memory and verbose and progress_callback:
        progress_callback("Include memory requested; disabling quiesce for this snapshot.")

    task = vm.CreateSnapshot_Task(name=name, description=description, memory=memory, quiesce=effective_quiesce)
    last_progress = -1
    while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
        current_progress = task.info.progress
        if current_progress is not None and current_progress != last_progress:
            last_progress = current_progress
            if progress_callback and verbose:
                progress_callback(f"Snapshot progress for VM {vm.summary.config.name}: {current_progress}%")
        time.sleep(1)

    if task.info.state == vim.TaskInfo.State.success:
        if progress_callback and verbose:
            progress_callback(f"Snapshot '{name}' created successfully for VM {vm.summary.config.name}")
        return True
    else:
        if progress_callback and verbose:
            progress_callback(f"Snapshot failed for VM {vm.summary.config.name}: {task.info.error}")
        return False

# ---------------------------------------------------------
# --------------- SEARCH + SNAPSHOT (PER VC) --------------
# ---------------------------------------------------------
def search_and_snapshot(vc: Dict, target: str, snapshot_name: str, snapshot_description: str,
                        include_memory=False, progress_callback: Optional[Callable[[str], None]] = None,
                        verbose=False, cache=None, skip_cache=False,
                        ssl_context: Optional[ssl.SSLContext] = None,
                        no_verify_flag: bool = False,
                        dry_run: bool = False) -> Dict:
    result = {
        "vcenter": vc["host"],
        "found": False,
        "snapshot_created": False,
        "vm_name": None,
        "error": None,
        "tls_unverified": False
    }
    si = None
    try:
        si, used_unverified = connect_to_vcenter(
            vc["host"], vc["user"], vc["password"],
            ssl_context=ssl_context,
            no_verify_flag=no_verify_flag,
            verbose=verbose, progress_callback=progress_callback
        )
        result["tls_unverified"] = bool(used_unverified)
        content = si.RetrieveContent()

        vm = find_vm_by_ip_or_name(content, vc["host"], target, cache=cache, skip_cache=skip_cache,
                                   progress_callback=progress_callback, verbose=verbose)

        if vm:
            result["found"] = True
            result["vm_name"] = vm.summary.config.name
            if verbose and progress_callback:
                progress_callback(f"Found VM '{vm.summary.config.name}' on {vc['host']}")

            if dry_run:
                if verbose and progress_callback:
                    progress_callback(f"[DRY RUN] Would create snapshot '{snapshot_name}' on {vm.summary.config.name}")
                result["snapshot_created"] = True  # indicate planned success
            else:
                success = create_snapshot(vm, snapshot_name, snapshot_description, memory=include_memory,
                                          progress_callback=progress_callback, verbose=verbose)
                result["snapshot_created"] = success
        else:
            if verbose and progress_callback:
                progress_callback(f"No VM matching '{target}' found on {vc['host']}")

    except Exception as e:
        result["error"] = str(e)
        if verbose and progress_callback:
            progress_callback(f"Error on {vc['host']}: {e}")
    finally:
        if si:
            Disconnect(si)
    return result

# ---------------------------------------------------------
# --------------- FULL-CACHE BUILDER (BATCHED) ------------
# ---------------------------------------------------------
def build_full_cache(vcenters: List[Dict], cache=None,
                     progress_callback: Optional[Callable[[str], None]] = None,
                     verbose=False, max_workers=1,
                     ssl_context: Optional[ssl.SSLContext] = None,
                     no_verify_flag: bool = False) -> Dict:
    """
    Build/refresh the global cache using batched PropertyCollector calls.
    Single-threaded by default; optional multi-thread across vCenters.
    """
    if cache is None:
        cache = {}

    if not cache_lock.acquire(blocking=False):
        if verbose and progress_callback:
            progress_callback("Cache rebuild already running, using existing cache...")
        return cache

    def _populate_for_vc(vc: Dict):
        si = None
        try:
            if verbose and progress_callback:
                progress_callback(f"Caching VMs from {vc['host']}...")

            si, used_unverified = connect_to_vcenter(
                vc["host"], vc["user"], vc["password"],
                ssl_context=ssl_context,
                no_verify_flag=no_verify_flag,
                verbose=verbose, progress_callback=progress_callback
            )
            content = si.RetrieveContent()
            vms = _collect_vms_properties(content, progress_callback=progress_callback, verbose=verbose)

            added = 0
            for entry in vms:
                vm = entry["obj"]
                props = entry["props"]
                extracted = _extract_search_keys(props)
                vm_data = {
                    "name": extracted["vm_data"]["name"],
                    "mo_ref": vm._moId,
                    "vcenter": vc["host"],
                    "ips": extracted["vm_data"]["ips"],
                }
                with cache_write_lock:
                    for k in extracted["keys"]:
                        cache[f"{vc['host']}::{k}"] = vm_data
                        added += 1

            if verbose and progress_callback:
                progress_callback(f"Cached {len(vms)} VMs ({added} keys) from {vc['host']}")

        except Exception as e:
            if verbose and progress_callback:
                progress_callback(f"Failed to cache {vc['host']}: {e}")
        finally:
            if si:
                Disconnect(si)

    try:
        if max_workers == 1:
            for vc in vcenters:
                _populate_for_vc(vc)
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = [ex.submit(_populate_for_vc, vc) for vc in vcenters]
                for f in as_completed(futures):
                    _ = f.result()
    finally:
        cache_lock.release()

    return cache

# ---------------------------------------------------------
# --------------------- ORCHESTRATION ---------------------
# ---------------------------------------------------------
def create_vm_snapshot(vcenters: List[Dict], target: str, snapshot_name: str, snapshot_description: str,
                       include_memory=False, progress_callback: Optional[Callable[[str], None]] = None,
                       verbose=False, max_workers=1, cache=None, skip_cache=False,
                       ssl_context: Optional[ssl.SSLContext] = None,
                       no_verify_flag: bool = False,
                       dry_run: bool = False) -> List[Dict]:
    results: List[Dict] = []

    # Single-threaded default (safer for vCenter)
    if max_workers == 1:
        for vc in vcenters:
            res = search_and_snapshot(vc, target, snapshot_name, snapshot_description, include_memory,
                                      progress_callback, verbose, cache, skip_cache, ssl_context,
                                      no_verify_flag, dry_run)
            results.append(res)
    else:
        # Multithread across vCenters (not inside a single vCenter)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_vc = {
                executor.submit(search_and_snapshot, vc, target, snapshot_name, snapshot_description,
                                include_memory, progress_callback, verbose, cache, skip_cache,
                                ssl_context, no_verify_flag, dry_run): vc
                for vc in vcenters
            }
            for future in as_completed(future_to_vc):
                res = future.result()
                results.append(res)
                # Preserve your original "stop on first Success"
                if res.get("snapshot_created"):
                    executor.shutdown(cancel_futures=True)
                    break
    return results

# ---------------------------------------------------------
# --------------------------- MAIN ------------------------
# ---------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VMware VM Snapshot Creator")
    # original flags (kept intact)
    parser.add_argument("--cred-file", default="vm_cred.enc")
    parser.add_argument("--key-file", default="vm_key.key")
    parser.add_argument("--cache-file", default="vm_cache.enc")
    parser.add_argument("--vm", required=True)
    parser.add_argument("--snapshot-name", required=True)
    parser.add_argument("--snapshot-desc", default="Created by script")
    parser.add_argument("--include-memory", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--skip-cache", action="store_true")
    parser.add_argument("--refresh-cache", action="store_true")
    parser.add_argument("--multithreaded", action="store_true", help="Enable multi-threaded snapshot search and cache")

    # new optional flags (do not change defaults)
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS verification to vCenter (always unverified)")
    parser.add_argument("--dry-run", action="store_true", help="Search and report but do not create a snapshot")
    parser.add_argument("--threads", type=int, default=None,
                        help="Number of vCenter threads (overrides --multithreaded). Safe default is 1")

    args = parser.parse_args()

    def print_progress(msg: str):
        print(msg)

    # SSL context (secure by default)
    ssl_context = build_ssl_context(args.no_verify)

    try:
        vcenters = load_encrypted_credentials(args.cred_file, args.key_file)
        cache = load_cache(args.cache_file, args.key_file)
    except Exception as e:
        print(f"Error loading credentials or cache: {e}")
        exit(1)

    # Determine worker count (backward compatible)
    if args.threads is not None:
        max_workers = max(1, int(args.threads))
    else:
        max_workers = 5 if args.multithreaded else 1  # original behavior

    # Optional full cache refresh (batched, lighter on vCenter)
    if args.refresh_cache:
        if args.verbose:
            print_progress("Refreshing global cache for all vCenters...")
        cache = build_full_cache(
            vcenters, cache=cache,
            progress_callback=print_progress, verbose=args.verbose,
            max_workers=max_workers, ssl_context=ssl_context,
            no_verify_flag=args.no_verify
        )
        save_cache(cache, args.cache_file, args.key_file)
        if args.verbose:
            print_progress("Global cache rebuilt successfully.")

    # Execute snapshot flow
    results = create_vm_snapshot(
        vcenters,
        target=args.vm,
        snapshot_name=args.snapshot_name,
        snapshot_description=args.snapshot_desc,
        include_memory=args.include_memory,
        progress_callback=print_progress,
        verbose=args.verbose,
        max_workers=max_workers,
        cache=cache,
        skip_cache=args.skip_cache,
        ssl_context=ssl_context,
        no_verify_flag=args.no_verify,
        dry_run=args.dry_run
    )

    # Persist cache unless explicitly skipped
    if not args.skip_cache:
        save_cache(cache, args.cache_file, args.key_file)

    print("\n--- Snapshot Results ---")
    for r in results:
        print(r)
