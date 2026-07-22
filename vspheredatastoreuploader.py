#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vSphere Upload Commander
------------------------
Midnight-Commander-style dual-pane TUI for uploading local files
to vSphere datastores directly from Linux.

LEFT  pane  — local filesystem (browse + select files to upload)
RIGHT pane  — vSphere: pick vCenter → pick Datastore → browse folders

Navigation:
  TAB           Switch active pane
  ↑ / ↓         Move cursor
  PgUp / PgDn   Page scroll
  ENTER         Open directory / enter datastore / enter folder
  BACKSPACE     Go up one level
  F5  or U      Upload selected local file to current vSphere path
  F7  or M      Create new folder (local pane) or new datastore folder (right pane)
  R             Refresh current pane
  /             Filter / search in current pane
  C             Connect to a vCenter (interactive dialog)
  S             Switch vCenter (if multiple loaded from cred file)
  Q / F10       Quit

Usage:
  # Encrypted cred file (same format as snapshot script):
  python vsphere_upload_mc.py --cred-file vm_cred.enc --key-file vm_key.key

  # Direct credentials:
  python vsphere_upload_mc.py --host vcenter.local --user admin@vsphere.local --password secret

  # Start local pane in a specific directory:
  python vsphere_upload_mc.py --host vc --user u --password p --local /data/isos
"""

import ssl
import os
import sys
import stat
import curses
import argparse
import threading
import shutil
import traceback
import time
import urllib.request
import urllib.parse
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any

# ── optional deps ──────────────────────────────────────────────────────────────
try:
    from pyVim.connect import SmartConnect, Disconnect
    from pyVmomi import vim
    PYVMOMI_OK = True
except ImportError:
    PYVMOMI_OK = False

try:
    from cryptography.fernet import Fernet
    FERNET_OK = True
except ImportError:
    FERNET_OK = False

# ── colour pair ids ────────────────────────────────────────────────────────────
C_HEADER   = 1
C_SELECTED = 2
C_NORMAL   = 3
C_DIR      = 4
C_STATUS   = 5
C_ERROR    = 6
C_TITLE    = 7
C_KEY      = 8
C_DIMMED   = 9
C_PROGRESS = 10
C_INACTIVE = 11

# ══════════════════════════════════════════════════════════════════════════════
# SSL / connection helpers  (same pattern as snapshot script)
# ══════════════════════════════════════════════════════════════════════════════
def _unverified_ctx():
    return ssl._create_unverified_context()

def _verified_ctx():
    return ssl.create_default_context()

CERT_ERRORS = (
    "CERTIFICATE_VERIFY_FAILED",
    "certificate verify failed",
    "unable to get local issuer certificate",
    "hostname mismatch",
)

def smart_connect(host: str, user: str, password: str):
    """Try verified TLS, fall back to unverified on cert errors."""
    for ctx_fn, label in [(_verified_ctx, "verified"), (_unverified_ctx, "unverified")]:
        try:
            si = SmartConnect(host=host, user=user, pwd=password, sslContext=ctx_fn())
            return si, label
        except Exception as exc:
            if label == "verified" and any(s in str(exc) for s in CERT_ERRORS):
                continue
            raise
    raise ConnectionError(f"Cannot connect to {host}")

# ══════════════════════════════════════════════════════════════════════════════
# Credential loader (same encrypted format as snapshot script)
# ══════════════════════════════════════════════════════════════════════════════
def load_credentials(cred_file: str, key_file: str) -> List[Dict]:
    if not FERNET_OK:
        raise RuntimeError("cryptography package not installed — pip install cryptography")
    with open(key_file, "rb") as f:
        key = f.read()
    fernet = Fernet(key)
    vcenters = []
    with open(cred_file, "rb") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            dec = fernet.decrypt(line).decode()
            parts = dec.split(",")
            if len(parts) != 3:
                continue
            h, u, p = parts
            vcenters.append({"host": h.strip(), "user": u.strip(), "password": p.strip()})
    return vcenters

# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════
def _fmt_size(n: int) -> str:
    if n < 0:
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"

def _url_q(s: str) -> str:
    return urllib.parse.quote(s, safe="")

def _trunc(s: str, width: int, pad=True) -> str:
    if len(s) > width:
        s = s[:max(0, width - 1)] + "…"
    return s.ljust(width) if pad else s

# ══════════════════════════════════════════════════════════════════════════════
# vSphere pane data model
# ══════════════════════════════════════════════════════════════════════════════
class VSEntry:
    """One row in the vSphere pane."""
    VCENTER   = "vcenter"
    DATASTORE = "datastore"
    DIR       = "dir"
    FILE      = "file"

    def __init__(self, name: str, kind: str, size: int = 0,
                 ds_path: str = "", ref=None, extra: str = ""):
        self.name     = name
        self.kind     = kind
        self.size     = size
        self.ds_path  = ds_path   # path inside datastore, e.g. "iso/ubuntu.iso"
        self.ref      = ref       # vim object if relevant
        self.extra    = extra     # display annotation

# ══════════════════════════════════════════════════════════════════════════════
# vSphere pane logic
# ══════════════════════════════════════════════════════════════════════════════
class VSpherePane:

    def __init__(self):
        self.si          = None
        self.content     = None
        self.connected   = False
        self.vc_host     = ""
        self.vc_user     = ""
        self.vc_password = ""
        self.tls_label   = ""

        self.entries: List[VSEntry] = []
        self.current_ds: Optional[vim.Datastore] = None
        self.current_ds_name: str = ""
        self.current_path: str = ""           # sub-folder inside the datastore

        # navigation history stack: list of (ds_name, ds_ref, path, entries)
        self._stack: List[Tuple] = []

        self.status = "Not connected — press C to connect, or pass --host"
        self._lock  = threading.Lock()
        self._uuid_to_name: Dict[str, str] = {}

    # ── connect / disconnect ──────────────────────────────────────────────────
    def connect(self, host: str, user: str, password: str) -> bool:
        try:
            si, label = smart_connect(host, user, password)
        except Exception as exc:
            self.status = f"Connect failed: {exc}"
            return False

        if self.si:
            try:
                Disconnect(self.si)
            except Exception:
                pass

        self.si          = si
        self.content     = si.RetrieveContent()
        self.connected   = True
        self.vc_host     = host
        self.vc_user     = user
        self.vc_password = password
        self.tls_label   = label
        self.status      = f"Connected ({label} TLS)"
        self._stack      = []
        self._uuid_to_name: Dict[str, str] = {}   # populated lazily
        self._build_uuid_map()
        self._load_datastores()
        return True

    def _build_uuid_map(self):
        """
        Build folder-name -> VM display-name map using PropertyCollector.

        Key insight: summary.config.vmPathName is ALWAYS populated (it comes
        from the datastore inventory, not the guest). It looks like:
            [DatastoreName] some-folder/vm-name.vmx
        The folder component is exactly what the datastore browser returns.

        We index every possible folder name variant so matching is robust:
          - The actual folder name from vmPathName  (most reliable)
          - summary.config.uuid     (BIOS UUID, sometimes used as folder)
          - summary.config.instanceUuid  (vCenter UUID, used on VMFS6)
        """
        view = None
        self._uuid_map_error = ""
        try:
            view = self.content.viewManager.CreateContainerView(
                self.content.rootFolder, [vim.VirtualMachine], True)

            traversal = vim.PropertyCollector.TraversalSpec(
                name="tSpec", path="view", skip=False,
                type=vim.view.ContainerView)

            prop_spec = vim.PropertyCollector.PropertySpec(
                type=vim.VirtualMachine, all=False,
                pathSet=[
                    "summary.config.name",           # display name - always present
                    "summary.config.vmPathName",      # [DS] folder/vm.vmx - always present
                    "summary.config.uuid",            # BIOS UUID
                    "summary.config.instanceUuid",    # vCenter UUID (folder name on VMFS6)
                ])

            obj_spec = vim.PropertyCollector.ObjectSpec(
                obj=view, selectSet=[traversal], skip=False)

            filt_spec = vim.PropertyCollector.FilterSpec(
                objectSet=[obj_spec], propSet=[prop_spec],
                reportMissingObjectsInResults=False)

            pc     = self.content.propertyCollector
            result = pc.RetrievePropertiesEx(
                specSet=[filt_spec],
                options=vim.PropertyCollector.RetrieveOptions())

            objects = []
            while True:
                if result and result.objects:
                    objects.extend(result.objects)
                if result and result.token:
                    result = pc.ContinueRetrievePropertiesEx(token=result.token)
                else:
                    break

            uuid_map: Dict[str, str] = {}
            for o in objects:
                props   = {dp.name: dp.val for dp in o.propSet}
                display = (props.get("summary.config.name") or "").strip()
                if not display:
                    continue

                # Primary key: folder name extracted from vmPathName
                # "[DS] some-folder/vm.vmx"  ->  "some-folder"
                vmx = (props.get("summary.config.vmPathName") or "").strip()
                if vmx:
                    after_bracket = vmx.split("]", 1)[-1].strip()  # "some-folder/vm.vmx"
                    folder = after_bracket.split("/")[0].strip()
                    if folder:
                        uuid_map[folder.lower()] = display

                # Fallback keys: uuid variants
                for key in ("summary.config.uuid", "summary.config.instanceUuid"):
                    val = (props.get(key) or "").strip().lower()
                    if val:
                        uuid_map[val] = display

            self._uuid_to_name   = uuid_map
            self._uuid_map_error = f"OK - {len(uuid_map)} entries"

        except Exception as exc:
            self._uuid_to_name   = {}
            self._uuid_map_error = f"uuid map error: {exc}"
        finally:
            if view:
                try:
                    view.Destroy()
                except Exception:
                    pass

    def disconnect(self):
        if self.si:
            try:
                Disconnect(self.si)
            except Exception:
                pass
        self.si = None
        self.connected = False

    # ── datastore listing ─────────────────────────────────────────────────────
    def _load_datastores(self):
        self.current_ds   = None
        self.current_ds_name = ""
        self.current_path = ""
        view = None
        try:
            view = self.content.viewManager.CreateContainerView(
                self.content.rootFolder, [vim.Datastore], True)
            entries = []
            for ds in view.view:
                try:
                    name = ds.summary.name
                    cap  = ds.summary.capacity or 0
                    free = ds.summary.freeSpace or 0
                    used = cap - free
                    pct  = int(used / cap * 100) if cap else 0
                    extra = f"{_fmt_size(free)} free / {_fmt_size(cap)} total  [{pct}% used]"
                    entries.append(VSEntry(name, VSEntry.DATASTORE, size=cap,
                                          ref=ds, extra=extra))
                except Exception:
                    pass
            entries.sort(key=lambda e: e.name.lower())
            self.entries = entries
        finally:
            if view:
                try:
                    view.Destroy()
                except Exception:
                    pass

    # ── navigation ────────────────────────────────────────────────────────────
    def enter(self, entry: VSEntry):
        if entry.kind == VSEntry.DATASTORE:
            self._stack.append(("__ds_list__", None, "", list(self.entries)))
            self.current_ds      = entry.ref
            self.current_ds_name = entry.ref.summary.name
            self.current_path    = ""
            self._browse("")
        elif entry.kind == VSEntry.DIR:
            self._stack.append((self.current_ds_name, self.current_ds,
                                 self.current_path, list(self.entries)))
            self.current_path = entry.ds_path
            self._browse(entry.ds_path)

    def go_up(self):
        if not self._stack:
            return
        label, ds_ref, path, entries = self._stack.pop()
        if label == "__ds_list__":
            self.current_ds      = None
            self.current_ds_name = ""
            self.current_path    = ""
        else:
            self.current_ds      = ds_ref
            self.current_ds_name = label
            self.current_path    = path
        self.entries = entries

    def refresh(self):
        if not self.connected:
            return
        self._build_uuid_map()   # pick up any renamed/new VMs
        if self.current_ds is None:
            self._load_datastores()
        else:
            self._browse(self.current_path)

    # ── folder browsing ───────────────────────────────────────────────────────
    def _browse(self, folder_path: str):
        if not self.current_ds:
            return
        try:
            browser  = self.current_ds.browser
            ds_name  = self.current_ds_name
            ds_path  = f"[{ds_name}]" + (f" {folder_path}" if folder_path else "")

            spec = vim.host.DatastoreBrowser.SearchSpec()
            spec.details = vim.host.DatastoreBrowser.FileInfo.Details(
                fileType=True, fileSize=True, modification=True)

            task = browser.SearchDatastore_Task(datastorePath=ds_path, searchSpec=spec)

            # Wait up to 30 s
            deadline = time.time() + 30
            while time.time() < deadline:
                state = task.info.state
                if state in (vim.TaskInfo.State.success, vim.TaskInfo.State.error):
                    break
                time.sleep(0.4)

            new_entries: List[VSEntry] = []
            if task.info.state == vim.TaskInfo.State.success:
                result = task.info.result
                for fi in (result.file if result else []):
                    fname = fi.path
                    if fname in (".", ".."):
                        continue
                    is_dir  = isinstance(fi, vim.host.DatastoreBrowser.FolderInfo)
                    subpath = (folder_path.rstrip("/") + "/" + fname).lstrip("/") \
                              if folder_path else fname
                    size    = getattr(fi, "fileSize", 0) or 0
                    kind    = VSEntry.DIR if is_dir else VSEntry.FILE

                    # Resolve UUID folder names → VM display name.
                    # Strip whitespace; try the raw name and lower-cased.
                    fname_clean = fname.strip()
                    vm_label = (self._uuid_to_name.get(fname_clean) or
                                self._uuid_to_name.get(fname_clean.lower()) or
                                "")
                    if vm_label:
                        display_name = f"{fname_clean}  \u2192 {vm_label}"
                    else:
                        display_name = fname_clean

                    new_entries.append(VSEntry(display_name, kind, size=size,
                                               ds_path=subpath, extra=vm_label))

            new_entries.sort(key=lambda e: (e.kind != VSEntry.DIR, e.name.lower()))
            self.entries = new_entries
        except Exception as exc:
            self.status  = f"Browse error: {exc}"
            self.entries = []

    # ── breadcrumb ────────────────────────────────────────────────────────────
    def breadcrumb(self) -> str:
        if not self.connected:
            return "vSphere (not connected)"
        if not self.current_ds_name:
            return f"{self.vc_host} › [select datastore]"
        crumb = f"{self.vc_host} › {self.current_ds_name}"
        if self.current_path:
            crumb += " › " + self.current_path.replace("/", " › ")
        return crumb

    def current_ds_path(self) -> str:
        """Full datastore path string for the current location."""
        if not self.current_ds_name:
            return ""
        p = f"[{self.current_ds_name}]"
        if self.current_path:
            p += f" {self.current_path}"
        return p

    # ── upload ────────────────────────────────────────────────────────────────
    def upload_file(self, local_path: str, progress_cb=None) -> Tuple[bool, str]:
        """
        Upload local_path to the current datastore folder.
        Uses the vSphere HTTPS /folder/ REST endpoint.
        Returns (success, message).
        """
        if not self.current_ds:
            return False, "No datastore selected — navigate into a datastore first"
        if not os.path.isfile(local_path):
            return False, f"Local file not found: {local_path}"

        fname    = os.path.basename(local_path)
        ds_name  = self.current_ds_name
        subpath  = (self.current_path.rstrip("/") + "/" + fname).lstrip("/") \
                   if self.current_path else fname
        dc_name  = self._datacenter_name()

        url = (f"https://{self.vc_host}/folder/"
               f"{_url_q(subpath)}"
               f"?dcPath={_url_q(dc_name)}&dsName={_url_q(ds_name)}")

        file_size = os.path.getsize(local_path)
        ctx = _unverified_ctx()

        try:
            with open(local_path, "rb") as fh:
                # Build a streaming PUT request
                req = urllib.request.Request(url, method="PUT")
                req.add_header("Cookie", self.si._stub.cookie)
                req.add_header("Content-Type", "application/octet-stream")
                req.add_header("Content-Length", str(file_size))

                # urllib doesn't stream properly; use http.client directly
                import http.client, ssl as _ssl
                parsed = urllib.parse.urlparse(url)
                conn = http.client.HTTPSConnection(
                    parsed.hostname, parsed.port or 443,
                    context=_ssl._create_unverified_context(), timeout=3600)

                qs = parsed.query
                path_with_qs = parsed.path + ("?" + qs if qs else "")

                conn.putrequest("PUT", path_with_qs)
                conn.putheader("Cookie", self.si._stub.cookie)
                conn.putheader("Content-Type", "application/octet-stream")
                conn.putheader("Content-Length", str(file_size))
                conn.putheader("Expect", "100-continue")
                conn.endheaders()

                chunk_size = 256 * 1024   # 256 KB
                sent = 0
                while True:
                    chunk = fh.read(chunk_size)
                    if not chunk:
                        break
                    conn.send(chunk)
                    sent += len(chunk)
                    if progress_cb and file_size:
                        progress_cb(sent, file_size)

                resp = conn.getresponse()
                conn.close()

                if resp.status in (200, 201):
                    self.refresh()
                    return True, f"Uploaded {fname} → {self.current_ds_path()}/{fname}"
                else:
                    body = resp.read(512).decode(errors="replace")
                    return False, f"HTTP {resp.status}: {body}"

        except Exception as exc:
            return False, f"Upload error: {exc}"

    def mkdir_ds(self, name: str) -> Tuple[bool, str]:
        """Create a folder inside the current datastore path."""
        if not self.current_ds:
            return False, "No datastore selected"
        try:
            fm       = self.content.fileManager
            ds_name  = self.current_ds_name
            sub      = (self.current_path.rstrip("/") + "/" + name).lstrip("/") \
                       if self.current_path else name
            new_path = f"[{ds_name}] {sub}"
            fm.MakeDirectory(name=new_path, createParentDirectories=True)
            self.refresh()
            return True, f"Created {new_path}"
        except Exception as exc:
            return False, f"Mkdir error: {exc}"

    def _datacenter_name(self) -> str:
        try:
            view = self.content.viewManager.CreateContainerView(
                self.content.rootFolder, [vim.Datacenter], True)
            try:
                for dc in view.view:
                    for d in dc.datastore:
                        if d._moId == self.current_ds._moId:
                            return dc.name
            finally:
                view.Destroy()
        except Exception:
            pass
        return "ha-datacenter"

# ══════════════════════════════════════════════════════════════════════════════
# Local filesystem pane
# ══════════════════════════════════════════════════════════════════════════════
class LocalEntry:
    __slots__ = ("name", "is_dir", "size", "path")
    def __init__(self, name, is_dir, size, path):
        self.name   = name
        self.is_dir = is_dir
        self.size   = size
        self.path   = path

class LocalPane:
    def __init__(self, start: str = "~"):
        self.cwd    = Path(start).expanduser().resolve()
        self.entries: List[LocalEntry] = []
        self.status = ""
        self.refresh()

    def refresh(self):
        entries = []
        try:
            for item in sorted(self.cwd.iterdir(),
                                key=lambda p: (not p.is_dir(), p.name.lower())):
                try:
                    s = item.stat()
                    is_dir = stat.S_ISDIR(s.st_mode)
                    entries.append(LocalEntry(
                        item.name, is_dir,
                        0 if is_dir else s.st_size,
                        str(item)))
                except PermissionError:
                    entries.append(LocalEntry(item.name + " [denied]", False, 0, str(item)))
        except PermissionError:
            self.status = "Permission denied"
        self.entries = entries

    def enter(self, entry: LocalEntry):
        if entry.is_dir:
            self.cwd = Path(entry.path).resolve()
            self.refresh()

    def go_up(self):
        parent = self.cwd.parent
        if parent != self.cwd:
            self.cwd = parent
            self.refresh()

    def mkdir(self, name: str) -> Tuple[bool, str]:
        target = self.cwd / name
        try:
            target.mkdir(parents=True, exist_ok=True)
            self.refresh()
            return True, f"Created {target}"
        except Exception as exc:
            return False, str(exc)

    def delete(self, entry: LocalEntry) -> Tuple[bool, str]:
        try:
            p = Path(entry.path)
            shutil.rmtree(p) if p.is_dir() else p.unlink()
            self.refresh()
            return True, f"Deleted {entry.name}"
        except Exception as exc:
            return False, str(exc)

    def breadcrumb(self) -> str:
        return str(self.cwd)

# ══════════════════════════════════════════════════════════════════════════════
# Main TUI
# ══════════════════════════════════════════════════════════════════════════════
class MC:

    def __init__(self, stdscr, local_start: str, init_vc: Optional[Dict],
                 all_vcenters: List[Dict]):
        self.scr         = stdscr
        self.local       = LocalPane(local_start)
        self.vs          = VSpherePane()
        self.all_vcenters = all_vcenters   # from cred file, for S=switch
        self.active      = 0          # 0=left, 1=right
        self.cursors     = [0, 0]
        self.offsets     = [0, 0]
        self.filter      = ["", ""]
        self.msg         = ""
        self.msg_err     = False

        # progress (upload runs in background thread)
        self._prog_text  = ""
        self._prog_pct   = -1
        self._prog_lock  = threading.Lock()
        self._uploading  = False

        self._init_colors()
        if init_vc:
            self._bg_connect(init_vc["host"], init_vc["user"], init_vc["password"])

    # ── colors ────────────────────────────────────────────────────────────────
    def _init_colors(self):
        curses.start_color()
        curses.use_default_colors()
        bg = -1
        curses.init_pair(C_HEADER,   curses.COLOR_BLACK,  curses.COLOR_CYAN)
        curses.init_pair(C_SELECTED, curses.COLOR_BLACK,  curses.COLOR_WHITE)
        curses.init_pair(C_NORMAL,   curses.COLOR_WHITE,  bg)
        curses.init_pair(C_DIR,      curses.COLOR_CYAN,   bg)
        curses.init_pair(C_STATUS,   curses.COLOR_BLACK,  curses.COLOR_GREEN)
        curses.init_pair(C_ERROR,    curses.COLOR_WHITE,  curses.COLOR_RED)
        curses.init_pair(C_TITLE,    curses.COLOR_YELLOW, bg)
        curses.init_pair(C_KEY,      curses.COLOR_BLACK,  curses.COLOR_YELLOW)
        curses.init_pair(C_DIMMED,   curses.COLOR_BLACK,  curses.COLOR_CYAN)
        curses.init_pair(C_PROGRESS, curses.COLOR_WHITE,  curses.COLOR_BLUE)
        curses.init_pair(C_INACTIVE, curses.COLOR_BLACK,  curses.COLOR_WHITE)
        curses.curs_set(0)
        self.scr.timeout(50)   # 50 ms tick — progress bar stays smooth

    # ── background connection ─────────────────────────────────────────────────
    def _bg_connect(self, host, user, password):
        self.set_msg(f"Connecting to {host} …")
        def _do():
            ok = self.vs.connect(host, user, password)
            self.cursors[1] = 0
            self.offsets[1] = 0
            if ok:
                n = len(self.vs._uuid_to_name)
                self.set_msg(f"Connected to {host} ({self.vs.tls_label} TLS) — {n} VMs mapped")
            else:
                self.set_msg(self.vs.status, error=True)
        threading.Thread(target=_do, daemon=True).start()

    # ── message bar ───────────────────────────────────────────────────────────
    def set_msg(self, text: str, error: bool = False):
        self.msg     = text
        self.msg_err = error

    # ── geometry ──────────────────────────────────────────────────────────────
    def _dims(self):
        rows, cols = self.scr.getmaxyx()
        pw = (cols - 1) // 2
        # Fixed rows: 0=title, 1=breadcrumb, 2=colhdr, rows-4=prog_label,
        #             rows-3=prog_bar, rows-2=msg, rows-1=keybar  → 7 fixed rows
        lh = max(1, rows - 7)
        # content rows: 3 .. 3+lh-1  i.e. up to rows-5  (leaves rows-4..rows-1 free)
        return rows, cols, pw, lh

    # ══════════════════════════════════════════════════════════════════════════
    # Drawing
    # ══════════════════════════════════════════════════════════════════════════
    def draw(self):
        self.scr.erase()
        rows, cols, pw, lh = self._dims()
        if rows < 10 or cols < 20:
            return

        # Row layout (fixed positions derived from rows):
        #   0          title
        #   1          breadcrumbs
        #   2          column headers
        #   3..3+lh-1  file lists   (lh = rows-7)
        #   rows-4     progress label
        #   rows-3     progress bar
        #   rows-2     message / status
        #   rows-1     key bar
        R_PROG_LBL = rows - 4
        R_PROG_BAR = rows - 3
        R_MSG      = rows - 2
        R_KEYS     = rows - 1

        # ── title ─────────────────────────────────────────────────────────────
        title = "  vSphere Upload Commander  "
        try:
            self.scr.attron(curses.color_pair(C_HEADER))
            self.scr.addstr(0, 0, " " * cols)
            self.scr.addstr(0, max(0, (cols - len(title)) // 2), title)
            self.scr.attroff(curses.color_pair(C_HEADER))
        except curses.error:
            pass

        # ── breadcrumbs ───────────────────────────────────────────────────────
        self._draw_bc(1, 0,    pw, self.local.breadcrumb(), self.active == 0)
        self._draw_bc(1, pw+1, pw, self.vs.breadcrumb(),    self.active == 1)

        # ── column headers ────────────────────────────────────────────────────
        self._draw_col_header(2, 0,    pw)
        self._draw_col_header(2, pw+1, pw)

        # ── vertical divider ──────────────────────────────────────────────────
        for r in range(1, R_PROG_LBL):
            try:
                self.scr.addch(r, pw, curses.ACS_VLINE)
            except curses.error:
                pass

        # ── pane file lists ───────────────────────────────────────────────────
        self._draw_local(3, 0,    pw, lh)
        self._draw_vs(   3, pw+1, pw, lh)

        # ── progress rows (always rendered) ───────────────────────────────────
        with self._prog_lock:
            pt  = self._prog_text
            pct = self._prog_pct

        if pt:
            # Label row
            try:
                self.scr.attron(curses.color_pair(C_PROGRESS) | curses.A_BOLD)
                self.scr.addstr(R_PROG_LBL, 0, _trunc(f" \u2191 {pt}", cols))
                self.scr.attroff(curses.color_pair(C_PROGRESS) | curses.A_BOLD)
            except curses.error:
                pass
            # Bar row — filled + empty sections
            bar_w  = max(1, cols - 1)
            filled = max(0, min(bar_w, int(bar_w * pct / 100))) if 0 <= pct <= 100 else 0
            empty  = bar_w - filled
            try:
                # filled portion (reversed = bright)
                if filled:
                    self.scr.attron(curses.color_pair(C_PROGRESS) | curses.A_REVERSE)
                    self.scr.addstr(R_PROG_BAR, 0, " " * filled)
                    self.scr.attroff(curses.color_pair(C_PROGRESS) | curses.A_REVERSE)
                # empty portion
                if empty:
                    self.scr.attron(curses.color_pair(C_DIMMED))
                    self.scr.addstr(R_PROG_BAR, filled, "\u2591" * empty)
                    self.scr.attroff(curses.color_pair(C_DIMMED))
                # percentage centred
                pct_str = f" {pct}% "
                mid = max(0, cols // 2 - len(pct_str) // 2)
                self.scr.attron(curses.color_pair(C_PROGRESS) | curses.A_BOLD)
                self.scr.addstr(R_PROG_BAR, mid, pct_str)
                self.scr.attroff(curses.color_pair(C_PROGRESS) | curses.A_BOLD)
            except curses.error:
                pass
        else:
            # Idle state — show empty bar outline so layout is always visible
            try:
                self.scr.attron(curses.color_pair(C_DIMMED))
                self.scr.addstr(R_PROG_LBL, 0, _trunc(" Ready ", cols))
                self.scr.addstr(R_PROG_BAR, 0, "\u2591" * min(cols - 1, cols))
                self.scr.attroff(curses.color_pair(C_DIMMED))
            except curses.error:
                pass

        # ── message bar ───────────────────────────────────────────────────────
        pair = C_ERROR if self.msg_err else C_STATUS
        try:
            self.scr.attron(curses.color_pair(pair))
            self.scr.addstr(R_MSG, 0, _trunc(" " + self.msg, cols))
            self.scr.attroff(curses.color_pair(pair))
        except curses.error:
            pass

        # ── key bar ───────────────────────────────────────────────────────────
        keys = [("TAB","Swap"), ("↑↓","Move"), ("ENT","Open"),
                ("←/-/U","Up"), ("F5/P","Upload"), ("F7/M","Mkdir"),
                ("R","Refresh"), ("/","Filter"), ("S","Switch VC"),
                ("C","Connect"), ("Q","Quit")]
        try:
            self.scr.attron(curses.color_pair(C_NORMAL))
            self.scr.addstr(R_KEYS, 0, " " * cols)
            self.scr.attroff(curses.color_pair(C_NORMAL))
            x = 0
            for k, lbl in keys:
                needed = len(k) + len(lbl) + 3
                if x + needed >= cols:
                    break
                self.scr.attron(curses.color_pair(C_KEY))
                self.scr.addstr(R_KEYS, x, f" {k} ")
                self.scr.attroff(curses.color_pair(C_KEY))
                x += len(k) + 2
                self.scr.attron(curses.color_pair(C_NORMAL))
                self.scr.addstr(R_KEYS, x, lbl + " ")
                self.scr.attroff(curses.color_pair(C_NORMAL))
                x += len(lbl) + 1
        except curses.error:
            pass

        self.scr.refresh()

    def _draw_bc(self, row, col, width, text, active):
        pair = C_TITLE if active else C_DIMMED
        try:
            self.scr.attron(curses.color_pair(pair))
            self.scr.addstr(row, col, _trunc(" " + text, width))
            self.scr.attroff(curses.color_pair(pair))
        except curses.error:
            pass

    def _draw_col_header(self, row, col, width):
        name_w = width - 12
        hdr    = _trunc("Name", name_w) + "       Size"
        try:
            self.scr.attron(curses.color_pair(C_INACTIVE) | curses.A_BOLD)
            self.scr.addstr(row, col, _trunc(hdr, width))
            self.scr.attroff(curses.color_pair(C_INACTIVE) | curses.A_BOLD)
        except curses.error:
            pass

    # ── render entries list ────────────────────────────────────────────────────
    def _draw_entries(self, top, left, width, height, entries, pane_idx,
                      is_local: bool):
        active = (self.active == pane_idx)
        cursor = self.cursors[pane_idx]
        offset = self.offsets[pane_idx]

        n = len(entries)
        cursor = max(0, min(cursor, n - 1)) if n else 0
        self.cursors[pane_idx] = cursor

        if cursor < offset:
            offset = cursor
        if cursor >= offset + height:
            offset = cursor - height + 1
        self.offsets[pane_idx] = offset

        size_w = 10
        name_w = max(4, width - size_w - 1)

        for i in range(height):
            idx = offset + i
            y   = top + i
            try:
                if idx >= n:
                    self.scr.addstr(y, left, " " * width)
                    continue

                entry    = entries[idx]
                selected = (idx == cursor) and active

                if is_local:
                    is_dir  = entry.is_dir
                    prefix  = "/" if is_dir else " "
                    disp_sz = "<DIR>" if is_dir else _fmt_size(entry.size)
                    label   = prefix + entry.name
                    extra   = ""
                else:
                    is_dir  = entry.kind in (VSEntry.DIR, VSEntry.DATASTORE)
                    if entry.kind == VSEntry.DATASTORE:
                        prefix  = "⊞ "
                        disp_sz = _fmt_size(entry.size)
                    elif is_dir:
                        prefix  = "/ "
                        disp_sz = "<DIR>"
                    else:
                        prefix  = "  "
                        disp_sz = _fmt_size(entry.size)
                    label   = prefix + entry.name
                    extra   = getattr(entry, "extra", "")

                # If it's a datastore row, show extra info instead of size
                if not is_local and entry.kind == VSEntry.DATASTORE and extra:
                    # Show name + extra squeezed into width
                    full_line = _trunc(label + "  " + extra, width)
                    if selected:
                        attr = curses.color_pair(C_SELECTED) | curses.A_BOLD
                    else:
                        attr = curses.color_pair(C_DIR)
                    self.scr.attron(attr)
                    self.scr.addstr(y, left, full_line[:width])
                    self.scr.attroff(attr)
                    continue

                name_part = _trunc(label, name_w, pad=True)
                size_part = disp_sz.rjust(size_w)
                line      = (name_part + size_part)[:width]

                if selected:
                    attr = curses.color_pair(C_SELECTED) | curses.A_BOLD
                elif is_dir:
                    attr = curses.color_pair(C_DIR)
                else:
                    attr = curses.color_pair(C_NORMAL)

                self.scr.attron(attr)
                self.scr.addstr(y, left, line)
                self.scr.attroff(attr)

            except curses.error:
                pass

    def _draw_local(self, top, left, width, height):
        filt    = self.filter[0].lower()
        entries = [e for e in self.local.entries
                   if not filt or filt in e.name.lower()]
        if not entries and not self.local.entries:
            try:
                self.scr.addstr(top, left, _trunc(" (empty)", width))
            except curses.error:
                pass
            return
        self._draw_entries(top, left, width, height, entries, 0, True)

    def _draw_vs(self, top, left, width, height):
        if not self.vs.connected:
            try:
                self.scr.attron(curses.color_pair(C_DIMMED))
                self.scr.addstr(top, left, _trunc(f" {self.vs.status}", width))
                self.scr.attroff(curses.color_pair(C_DIMMED))
                self.scr.addstr(top+1, left, _trunc(" C = connect  S = switch VC", width))
            except curses.error:
                pass
            return
        filt    = self.filter[1].lower()
        entries = [e for e in self.vs.entries
                   if not filt or filt in e.name.lower()]
        self._draw_entries(top, left, width, height, entries, 1, False)

    # ══════════════════════════════════════════════════════════════════════════
    # Prompt helper
    # ══════════════════════════════════════════════════════════════════════════
    def _prompt(self, label: str, secret: bool = False,
                initial: str = "") -> str:
        rows, cols, _, _ = self._dims()
        row   = rows // 2
        width = min(70, cols - 4)
        x     = (cols - width) // 2
        buf   = list(initial)
        curses.curs_set(1)
        while True:
            try:
                self.scr.attron(curses.color_pair(C_HEADER))
                self.scr.addstr(row, x, " " * width)
                disp = "•" * len(buf) if secret else "".join(buf)
                self.scr.addstr(row, x, _trunc(label + disp, width, pad=False))
                self.scr.attroff(curses.color_pair(C_HEADER))
                self.scr.refresh()
            except curses.error:
                pass
            ch = self.scr.getch()
            if ch in (10, 13):
                break
            elif ch == 27:
                buf = []
                break
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                if buf:
                    buf.pop()
            elif 32 <= ch < 127:
                buf.append(chr(ch))
        curses.curs_set(0)
        return "".join(buf)

    def _confirm_dialog(self, lines: List[str]) -> bool:
        """Show a centred confirmation box. Returns True if user presses Y."""
        rows, cols, _, _ = self._dims()
        width  = min(70, cols - 4)
        height = len(lines) + 4   # border + lines + blank + [Y] [N] row
        y = max(0, (rows - height) // 2)
        x = max(0, (cols - width)  // 2)
        curses.curs_set(0)
        while True:
            try:
                # Box outline
                self.scr.attron(curses.color_pair(C_HEADER))
                self.scr.addstr(y, x, "┌" + "─" * (width - 2) + "┐")
                for i, line in enumerate(lines):
                    self.scr.addstr(y + 1 + i, x, "│" + _trunc(f"  {line}", width - 2) + "│")
                self.scr.addstr(y + 1 + len(lines), x, "│" + " " * (width - 2) + "│")
                btn = "│" + _trunc("      [ Y ] confirm       [ N ] cancel", width - 2, pad=True) + "│"
                self.scr.addstr(y + 2 + len(lines), x, btn)
                self.scr.addstr(y + 3 + len(lines), x, "└" + "─" * (width - 2) + "┘")
                self.scr.attroff(curses.color_pair(C_HEADER))
                self.scr.refresh()
            except curses.error:
                pass
            ch = self.scr.getch()
            if ch in (ord('y'), ord('Y'), ord('\n'), 10, 13):
                return True
            elif ch in (ord('n'), ord('N'), 27, ord('q'), ord('Q')):
                return False
        """Simple selection dialog; returns index or -1."""
        if not items:
            return -1
        rows, cols, _, _ = self._dims()
        width  = min(60, cols - 4)
        height = min(len(items) + 2, rows - 4)
        x      = (cols - width) // 2
        y      = (rows - height) // 2
        sel    = 0
        curses.curs_set(0)
        while True:
            try:
                self.scr.attron(curses.color_pair(C_HEADER))
                self.scr.addstr(y, x, _trunc(f" {title} ", width))
                self.scr.attroff(curses.color_pair(C_HEADER))
                for i, item in enumerate(items):
                    if i >= height - 2:
                        break
                    pair = C_SELECTED if i == sel else C_NORMAL
                    self.scr.attron(curses.color_pair(pair))
                    self.scr.addstr(y + 1 + i, x, _trunc(f"  {item}  ", width))
                    self.scr.attroff(curses.color_pair(pair))
                self.scr.refresh()
            except curses.error:
                pass
            ch = self.scr.getch()
            if ch == curses.KEY_UP:
                sel = max(0, sel - 1)
            elif ch == curses.KEY_DOWN:
                sel = min(len(items) - 1, sel + 1)
            elif ch in (10, 13):
                return sel
            elif ch == 27:
                return -1

    # ══════════════════════════════════════════════════════════════════════════
    # Actions
    # ══════════════════════════════════════════════════════════════════════════
    def _action_upload(self):
        """Upload the selected local file to the current vSphere path."""
        if self._uploading:
            self.set_msg("Upload already in progress…", error=True)
            return
        entry = self._local_sel()
        if not entry:
            self.set_msg("No file selected in local pane", error=True)
            return
        if entry.is_dir:
            self.set_msg("Select a file (not a directory) to upload", error=True)
            return
        if not self.vs.connected:
            self.set_msg("Not connected to vSphere — press C to connect", error=True)
            return
        if not self.vs.current_ds_name:
            self.set_msg("Navigate into a datastore (right pane) before uploading", error=True)
            return

        local_path = entry.path
        ds_dest    = self.vs.current_ds_path()

        confirmed = self._confirm_dialog([
            f"File:        {entry.name}",
            f"Size:        {_fmt_size(entry.size)}",
            f"Destination: {ds_dest}",
        ])
        if not confirmed:
            self.set_msg("Upload cancelled")
            return

        self._uploading = True
        self.set_msg(f"Uploading {entry.name} …")

        def _do():
            def _progress(sent, total):
                pct = int(sent / total * 100) if total else 0
                txt = (f"Uploading {entry.name}: {pct}%  "
                       f"{_fmt_size(sent)} / {_fmt_size(total)}")
                with self._prog_lock:
                    self._prog_text = txt
                    self._prog_pct  = pct
                # Wake the main curses loop immediately so bar repaints
                try:
                    curses.ungetch(0)
                except Exception:
                    pass

            ok, msg = self.vs.upload_file(local_path, progress_cb=_progress)
            with self._prog_lock:
                self._prog_text = ""
                self._prog_pct  = -1
            self._uploading = False
            self.set_msg(msg, error=not ok)
            try:
                curses.ungetch(0)
            except Exception:
                pass

        threading.Thread(target=_do, daemon=True).start()

    def _action_mkdir(self):
        if self.active == 0:
            name = self._prompt("New local folder name: ")
            if name:
                ok, msg = self.local.mkdir(name)
                self.set_msg(msg, error=not ok)
        else:
            if not self.vs.connected or not self.vs.current_ds_name:
                self.set_msg("Navigate into a datastore first", error=True)
                return
            name = self._prompt("New datastore folder name: ")
            if name:
                ok, msg = self.vs.mkdir_ds(name)
                self.set_msg(msg, error=not ok)

    def _action_connect(self):
        host = self._prompt("vCenter host: ")
        if not host:
            return
        user = self._prompt("Username: ")
        if not user:
            return
        pwd  = self._prompt("Password: ", secret=True)
        self._bg_connect(host, user, pwd)

    def _action_switch_vc(self):
        if not self.all_vcenters:
            self.set_msg("No vCenters loaded from cred file — use C to connect manually",
                         error=True)
            return
        labels = [vc["host"] for vc in self.all_vcenters]
        idx = self._pick_from_list("Select vCenter", labels)
        if idx < 0:
            return
        vc = self.all_vcenters[idx]
        self._bg_connect(vc["host"], vc["user"], vc["password"])

    def _action_filter(self):
        side = "local" if self.active == 0 else "vSphere"
        filt = self._prompt(f"Filter {side} ({self.filter[self.active] or 'none'}): ")
        self.filter[self.active] = filt
        self.cursors[self.active] = 0
        self.offsets[self.active] = 0

    def _action_enter(self):
        if self.active == 0:
            entry = self._local_sel()
            if entry and entry.is_dir:
                self.local.enter(entry)
                self.cursors[0] = 0
                self.offsets[0] = 0
        else:
            entry = self._vs_sel()
            if entry and entry.kind in (VSEntry.DATASTORE, VSEntry.DIR):
                def _browse():
                    self.vs.enter(entry)
                    self.cursors[1] = 0
                    self.offsets[1] = 0
                threading.Thread(target=_browse, daemon=True).start()

    def _action_up(self):
        if self.active == 0:
            self.local.go_up()
            self.cursors[0] = 0
            self.offsets[0] = 0
        else:
            self.vs.go_up()
            self.cursors[1] = 0
            self.offsets[1] = 0

    def _action_refresh(self):
        if self.active == 0:
            self.local.refresh()
            self.set_msg("Local pane refreshed")
        else:
            threading.Thread(target=self.vs.refresh, daemon=True).start()
            self.set_msg("vSphere pane refreshing…")

    # ── selection helpers ─────────────────────────────────────────────────────
    def _local_filtered(self):
        filt = self.filter[0].lower()
        return [e for e in self.local.entries if not filt or filt in e.name.lower()]

    def _vs_filtered(self):
        filt = self.filter[1].lower()
        return [e for e in self.vs.entries if not filt or filt in e.name.lower()]

    def _local_sel(self) -> Optional[LocalEntry]:
        lst = self._local_filtered()
        c   = self.cursors[0]
        return lst[c] if 0 <= c < len(lst) else None

    def _vs_sel(self) -> Optional[VSEntry]:
        lst = self._vs_filtered()
        c   = self.cursors[1]
        return lst[c] if 0 <= c < len(lst) else None

    # ── cursor movement ───────────────────────────────────────────────────────
    def _move(self, delta: int):
        lst   = self._local_filtered() if self.active == 0 else self._vs_filtered()
        limit = max(0, len(lst) - 1)
        self.cursors[self.active] = max(0, min(limit,
                                               self.cursors[self.active] + delta))

    def _dump_uuid_map(self):
        """Write the current uuid→name map to /tmp/vsphere_mc_debug.txt."""
        path = "/tmp/vsphere_mc_debug.txt"
        try:
            with open(path, "w") as f:
                f.write(f"vCenter: {self.vs.vc_host}\n")
                f.write(f"Map status: {getattr(self.vs, '_uuid_map_error', 'n/a')}\n")
                f.write(f"Total entries: {len(self.vs._uuid_to_name)}\n\n")
                f.write("Current pane entries:\n")
                for e in self.vs.entries:
                    f.write(f"  fname={e.name!r}  ds_path={e.ds_path!r}  extra={e.extra!r}\n")
                f.write("\nUUID map (folder_key → VM name):\n")
                for k, v in sorted(self.vs._uuid_to_name.items()):
                    f.write(f"  {k!r:60s} → {v!r}\n")
            self.set_msg(f"Debug dump written to {path}")
        except Exception as exc:
            self.set_msg(f"Dump failed: {exc}", error=True)

    # ══════════════════════════════════════════════════════════════════════════
    # Main event loop
    # ══════════════════════════════════════════════════════════════════════════
    def run(self):
        while True:
            self.draw()
            ch = self.scr.getch()

            if ch in (-1, 0):
                continue   # timeout or synthetic wakeup — draw() repaints progress

            # ── quit ──────────────────────────────────────────────────────────
            if ch in (ord('q'), ord('Q'), curses.KEY_F10):
                break

            # ── pane switch ───────────────────────────────────────────────────
            elif ch == 9:   # TAB
                self.active = 1 - self.active

            # ── movement ──────────────────────────────────────────────────────
            elif ch == curses.KEY_UP:
                self._move(-1)
            elif ch == curses.KEY_DOWN:
                self._move(1)
            elif ch == curses.KEY_PPAGE:
                _, _, _, lh = self._dims()
                self._move(-lh)
            elif ch == curses.KEY_NPAGE:
                _, _, _, lh = self._dims()
                self._move(lh)
            elif ch == curses.KEY_HOME:
                self.cursors[self.active] = 0
            elif ch == curses.KEY_END:
                lst = self._local_filtered() if self.active == 0 else self._vs_filtered()
                self.cursors[self.active] = max(0, len(lst) - 1)

            # ── enter / open ──────────────────────────────────────────────────
            elif ch in (10, 13, curses.KEY_ENTER):
                self._action_enter()

            # ── go up ─────────────────────────────────────────────────────────
            elif ch in (curses.KEY_BACKSPACE, curses.KEY_LEFT, 127, 8,
                        ord('-'), ord('u'), ord('U')):
                self._action_up()

            # ── upload ────────────────────────────────────────────────────────
            elif ch in (curses.KEY_F5, ord('p'), ord('P')):
                self._action_upload()

            # ── mkdir ─────────────────────────────────────────────────────────
            elif ch in (curses.KEY_F7, ord('m'), ord('M')):
                self._action_mkdir()

            # ── refresh ───────────────────────────────────────────────────────
            elif ch in (ord('r'), ord('R')):
                self._action_refresh()

            # ── filter ────────────────────────────────────────────────────────
            elif ch == ord('/'):
                self._action_filter()

            # ── connect ───────────────────────────────────────────────────────
            elif ch in (ord('c'), ord('C')):
                self._action_connect()

            # ── switch vCenter ────────────────────────────────────────────────
            elif ch in (ord('s'), ord('S')):
                self._action_switch_vc()

            # ── clear filter ──────────────────────────────────────────────────
            elif ch == 27:   # ESC
                self.filter[self.active] = ""
                self.set_msg("Filter cleared")

            # ── debug: dump uuid map to /tmp ──────────────────────────────────
            elif ch in (ord('d'), ord('D')):
                self._dump_uuid_map()

# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════
def _curses_main(stdscr, args):
    all_vcenters: List[Dict] = []
    init_vc: Optional[Dict]  = None

    if args.host:
        if not args.user or not args.password:
            stdscr.addstr(0, 0, "ERROR: --host requires --user and --password")
            stdscr.getch()
            return
        init_vc = {"host": args.host, "user": args.user, "password": args.password}

    elif args.cred_file and args.key_file:
        try:
            all_vcenters = load_credentials(args.cred_file, args.key_file)
            if all_vcenters:
                init_vc = all_vcenters[0]
        except Exception as exc:
            stdscr.addstr(0, 0, f"Credential load error: {exc}  — press any key")
            stdscr.getch()

    app = MC(stdscr, local_start=args.local or "~",
             init_vc=init_vc, all_vcenters=all_vcenters)
    try:
        app.run()
    finally:
        app.vs.disconnect()

def main():
    parser = argparse.ArgumentParser(
        description="vSphere Upload Commander — dual-pane datastore file manager")

    cred = parser.add_argument_group("Direct credentials")
    cred.add_argument("--host",     help="vCenter hostname / IP")
    cred.add_argument("--user",     help="vCenter username")
    cred.add_argument("--password", help="vCenter password")

    enc = parser.add_argument_group("Encrypted credential file")
    enc.add_argument("--cred-file", help="Encrypted credentials file (vm_cred.enc)")
    enc.add_argument("--key-file",  help="Fernet key file (vm_key.key)")

    parser.add_argument("--local", default="~",
                        help="Starting directory for local pane (default: ~)")
    args = parser.parse_args()

    if not PYVMOMI_OK:
        print("ERROR: pyVmomi is not installed.")
        print("       pip install pyVmomi")
        sys.exit(1)

    try:
        curses.wrapper(_curses_main, args)
    except KeyboardInterrupt:
        pass
    except Exception:
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
