#!/usr/bin/env python3
"""
Foreman/Katello Pipeline Orchestrator

Reads a YAML config file defining sync -> publish -> promote pipelines.
Each pipeline:
  1) Syncs configured repositories IN PARALLEL
  2) Waits for all syncs to complete (aborts pipeline on any failure)
  3) Publishes the Content View
  4) Optionally promotes to a lifecycle environment
  5) Prunes the oldest safe version

Usage:
  foreman_pipeline.py [--config FILE] [--pipeline NAME] [--dry-run] [--list]

Environment variables:
  HAMMER_TOKEN      required
  HAMMER_USER       default: admin
  FOREMAN_SERVER    optional if hammer.yml already configured
  FOREMAN_CONFIG    default config path if --config not given
  SYNC_POLL_INTERVAL  seconds between task status polls (default: 15)
  SYNC_TIMEOUT        seconds before a sync is abandoned (default: 3600)
  LOG_DIR           directory for log files (default: /var/log/foreman-publish)
  LOCK_DIR          directory for lock files (default: /var/lock)
"""

from __future__ import annotations

import argparse
import datetime
import fcntl
import logging
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    sys.exit("Missing dependency: pip install pyyaml")


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
LOG_FMT = "%(asctime)s  %(levelname)-8s  %(message)s"
DATE_FMT = "%Y-%m-%d %H:%M:%S"

class ColouredFormatter(logging.Formatter):
    COLOURS = {
        logging.DEBUG:    "\033[0;37m",
        logging.INFO:     "\033[0;36m",
        logging.WARNING:  "\033[1;33m",
        logging.ERROR:    "\033[0;31m",
        logging.CRITICAL: "\033[1;31m",
    }
    RESET = "\033[0m"
    GREEN = "\033[0;32m"

    def format(self, record: logging.LogRecord) -> str:
        colour = self.COLOURS.get(record.levelno, self.RESET)
        ts = datetime.datetime.fromtimestamp(record.created).strftime(DATE_FMT)
        msg = record.getMessage()

        # Special prefix tokens for sub-messages
        if msg.startswith("✔ "):
            prefix = f"{self.GREEN}  ✔{self.RESET} "
            msg = msg[2:]
        elif msg.startswith("⚠ "):
            prefix = f"\033[1;33m  ⚠{self.RESET} "
            msg = msg[2:]
        elif msg.startswith("✘ "):
            prefix = f"\033[0;31m  ✘{self.RESET} "
            msg = msg[2:]
        elif msg.startswith("  "):
            prefix = ""
        else:
            prefix = f"{colour}==>{self.RESET} "

        return f"{ts}  {prefix}{msg}"


def setup_logging(log_dir: str) -> logging.Logger:
    logger = logging.getLogger("foreman")
    logger.setLevel(logging.DEBUG)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(ColouredFormatter())
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)

    # File handler
    try:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = Path(log_dir) / f"foreman_pipeline_{stamp}.log"
        fh = logging.FileHandler(log_path)
        fh.setFormatter(logging.Formatter(LOG_FMT, datefmt=DATE_FMT))
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)
    except OSError:
        logger.warning("⚠ Could not open log file in %s — logging to console only", log_dir)

    return logger


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DEFAULT_CONFIG  = os.environ.get("FOREMAN_CONFIG", "/etc/foreman-publish/pipelines.yaml")
DEFAULT_LOG_DIR = os.environ.get("LOG_DIR",  "/var/log/foreman-publish")
DEFAULT_LOCK_DIR = os.environ.get("LOCK_DIR", "/var/lock")
SYNC_POLL_INTERVAL = int(os.environ.get("SYNC_POLL_INTERVAL", "15"))
SYNC_TIMEOUT       = int(os.environ.get("SYNC_TIMEOUT",       "3600"))


# ---------------------------------------------------------------------------
# Hammer wrapper
# ---------------------------------------------------------------------------
class HammerError(Exception):
    pass


class Hammer:
    """Thin wrapper around the hammer CLI."""

    def __init__(self, dry_run: bool = False):
        self.user   = os.environ.get("HAMMER_USER", "admin")
        self.token  = os.environ.get("HAMMER_TOKEN", "")
        self.server = os.environ.get("FOREMAN_SERVER", "")
        self.dry_run = dry_run

        if not self.token:
            raise HammerError("HAMMER_TOKEN is not set")

        # Verify hammer is on PATH
        try:
            subprocess.run(["hammer", "--version"],
                           capture_output=True, check=True, timeout=10)
        except FileNotFoundError:
            raise HammerError("hammer CLI not found — is it installed and on PATH?")
        except subprocess.CalledProcessError:
            pass  # some versions exit non-zero for --version, that's fine

    def _base_cmd(self) -> List[str]:
        cmd = ["hammer", "--username", self.user, "--password", self.token]
        if self.server:
            cmd += ["--server", self.server]
        return cmd

    def run(self, *args: str, org: str = None) -> str:
        """
        Run hammer with the given args. Injects --organization if provided,
        falls back without it if hammer rejects it.
        Returns stdout as a string.
        """
        cmd = self._base_cmd() + list(args)
        if org:
            cmd += ["--organization", org]

        if self.dry_run:
            log = logging.getLogger("foreman")
            log.info("  DRY-RUN: %s", " ".join(cmd))
            return "DRY_RUN"

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            raise HammerError(f"hammer timed out: {' '.join(args)}")

        if result.returncode != 0 and org:
            stderr_lower = result.stderr.lower()
            if "unrecognised option" in stderr_lower and "organization" in stderr_lower:
                return self.run(*args)   # retry without org

        if result.returncode != 0:
            err = (result.stderr.strip() or result.stdout.strip())
            raise HammerError(f"hammer {' '.join(args[:2])} failed: {err}")

        return result.stdout

    def run_async(self, *args: str, org: str = None) -> str:
        """Like run() but expects --async output; returns the task UUID."""
        out = self.run(*args, "--async", org=org)
        if self.dry_run:
            return "dry-run-task-id"
        match = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                          out, re.IGNORECASE)
        if not match:
            raise HammerError(f"Could not find task UUID in output: {out!r}")
        return match.group(0)

    def task_state(self, task_id: str) -> Tuple[str, str]:
        """Poll a task; returns (state, result) both lowercased."""
        out = self.run("task", "info", "--id", task_id)
        state = result = ""
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith("State"):
                state = stripped.split(":", 1)[-1].strip().lower()
            elif stripped.startswith("Result"):
                result = stripped.split(":", 1)[-1].strip().lower()
        return state, result


# ---------------------------------------------------------------------------
# Table parser (shared with the config generator)
# ---------------------------------------------------------------------------
def parse_name_column(raw: str, exclude: List[str] = None) -> List[str]:
    exclude_set = set(exclude or [])
    col_index = None
    results = []
    for line in raw.splitlines():
        if re.match(r'^[\s\-|]+$', line):
            continue
        parts = [p.strip() for p in line.split("|") if p.strip()]
        if col_index is None:
            if "NAME" in parts:
                col_index = parts.index("NAME")
            continue
        if len(parts) > col_index:
            val = parts[col_index]
            if val and val not in exclude_set:
                results.append(val)
    return results


# ---------------------------------------------------------------------------
# CV version table parser
# Returns list of dicts: {id, version, envs}
# ---------------------------------------------------------------------------
def parse_cv_versions(raw: str) -> List[Dict]:
    """
    Parse 'content-view version list' output.
    Columns: ID | NAME | VERSION | LIFECYCLE ENVIRONMENTS | ...
    We find ID, VERSION, and the environments column dynamically.
    """
    col_id = col_ver = col_env = None
    versions = []

    for line in raw.splitlines():
        if re.match(r'^[\s\-|]+$', line):
            continue
        parts = [p.strip() for p in line.split("|")]
        # Remove empty edge parts
        parts = [p for p in parts if p != ""] if parts[0] == "" else parts

        if col_id is None:
            # Header row detection
            upper = [p.upper() for p in parts]
            if "ID" in upper:
                col_id  = upper.index("ID")
                # VERSION might be labelled "VERSION"
                col_ver = upper.index("VERSION") if "VERSION" in upper else None
                # Environments column
                for label in ("LIFECYCLE ENVIRONMENTS", "ENVIRONMENTS", "LIFECYCLE"):
                    if label in upper:
                        col_env = upper.index(label)
                        break
            continue

        if col_id is None or len(parts) <= col_id:
            continue

        vid = parts[col_id]
        if not vid.isdigit():
            continue

        ver  = parts[col_ver].strip() if col_ver is not None and len(parts) > col_ver else ""
        envs = parts[col_env].strip() if col_env is not None and len(parts) > col_env else ""

        versions.append({"id": vid, "version": ver, "envs": envs})

    return versions


# ---------------------------------------------------------------------------
# Per-pipeline file lock (prevent concurrent cron runs of the same pipeline)
# ---------------------------------------------------------------------------
class PipelineLock:
    def __init__(self, name: str, lock_dir: str):
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
        self.path = Path(lock_dir) / f"foreman_pipeline_{safe_name}.lock"
        self._fh = None

    def __enter__(self):
        self._fh = open(self.path, "w")
        try:
            fcntl.flock(self._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._fh.close()
            raise RuntimeError(
                f"Pipeline is already running (lock file: {self.path}). "
                "Remove the lock file if this is incorrect."
            )
        return self

    def __exit__(self, *_):
        if self._fh:
            fcntl.flock(self._fh, fcntl.LOCK_UN)
            self._fh.close()
            try:
                self.path.unlink()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Repo entry helpers — repos in config can be plain strings (legacy) or
# {name, product} dicts produced by foreman_config_gen.py
# ---------------------------------------------------------------------------
def repo_entry_name(r) -> str:
    return r['name'] if isinstance(r, dict) else r

def repo_entry_product(r) -> str:
    return r.get('product', '') if isinstance(r, dict) else ''


# ---------------------------------------------------------------------------
# Repo sync worker (runs in a thread)
# ---------------------------------------------------------------------------
def sync_repo(hammer: Hammer, org: str, repo_name: str, product: str,
              logger: logging.Logger) -> Tuple[str, bool]:
    """
    Sync a single repository. Returns (repo_name, success).
    Designed to run in a thread pool.
    """
    logger.info("  Starting sync: '%s' (product: '%s')", repo_name, product)

    if hammer.dry_run:
        logger.info("✔ DRY-RUN sync complete: '%s'", repo_name)
        return repo_name, True

    # Kick off async sync
    try:
        task_id = hammer.run_async(
            "repository", "synchronize", "--name", repo_name, "--product", product,
            org=org,
        )
    except HammerError as e:
        logger.error("✘ Failed to start sync for '%s': %s", repo_name, e)
        return repo_name, False

    logger.info("  Sync task %s started for '%s'", task_id, repo_name)

    # Poll until done or timeout
    elapsed = 0
    while elapsed < SYNC_TIMEOUT:
        time.sleep(SYNC_POLL_INTERVAL)
        elapsed += SYNC_POLL_INTERVAL

        try:
            state, result = hammer.task_state(task_id)
        except HammerError as e:
            logger.warning("⚠ Could not poll task %s (%ds elapsed): %s", task_id, elapsed, e)
            continue

        if state in ("stopped", "paused"):
            if result == "success":
                logger.info("✔ Sync complete: '%s'", repo_name)
                return repo_name, True
            else:
                logger.error("✘ Sync FAILED for '%s': state=%s result=%s", repo_name, state, result)
                return repo_name, False
        elif state in ("running", "pending", "planning"):
            logger.info("  '%s' — %s (%ds elapsed)", repo_name, state, elapsed)
        else:
            logger.warning("⚠ Unknown task state '%s' for '%s' — continuing to poll", state, repo_name)

    logger.error("✘ Sync TIMED OUT for '%s' after %ds", repo_name, SYNC_TIMEOUT)
    return repo_name, False


# ---------------------------------------------------------------------------
# CV publish / promote / prune
# ---------------------------------------------------------------------------
def get_cv_versions(hammer: Hammer, org: str, cv: str) -> List[Dict]:
    raw = hammer.run("content-view", "version", "list", "--content-view", cv, org=org)
    if hammer.dry_run:
        return []
    return parse_cv_versions(raw)


def version_sort_key(v: Dict) -> List[int]:
    """Sort by version number components numerically."""
    try:
        return [int(x) for x in v["version"].split(".")]
    except (ValueError, AttributeError):
        return [0]


# ---------------------------------------------------------------------------
# Generic task poller — used for publish, promote, delete
# ---------------------------------------------------------------------------
def poll_task(hammer: Hammer, task_id: str, label: str,
              logger: logging.Logger,
              poll_interval: int = None,
              timeout: int = None) -> None:
    """
    Poll a Foreman task until it succeeds or fails.
    Raises RuntimeError on failure or timeout.
    """
    poll_interval = poll_interval or SYNC_POLL_INTERVAL
    timeout       = timeout or SYNC_TIMEOUT
    elapsed = 0

    while elapsed < timeout:
        time.sleep(poll_interval)
        elapsed += poll_interval

        try:
            state, result = hammer.task_state(task_id)
        except HammerError as exc:
            logger.warning("⚠ Could not poll task %s (%ds): %s", task_id, elapsed, exc)
            continue

        if state in ("stopped", "paused"):
            if result == "success":
                return
            raise RuntimeError(
                f"{label} task failed: state={state} result={result} "
                f"(task id: {task_id})"
            )
        elif state in ("running", "pending", "planning"):
            logger.info("  %s — %s (%ds elapsed)", label, state, elapsed)
        else:
            logger.warning("⚠ Unknown task state '%s' for %s — continuing",
                           state, label)

    raise RuntimeError(f"{label} timed out after {timeout}s (task id: {task_id})")


def publish_and_prune(
    hammer: Hammer,
    org: str,
    cv: str,
    lifecycle_env: str,
    do_promote: bool,
    min_keep: int,
    logger: logging.Logger,
) -> None:

    logger.info("Publishing Content View: '%s' (org='%s')", cv, org)

    before_versions = get_cv_versions(hammer, org, cv)
    before_max = max(before_versions, key=version_sort_key)["version"] \
        if before_versions else None
    logger.info("  Before: count=%d  max=%s", len(before_versions), before_max or "<none>")

    # Publish async — can take many minutes for large Red Hat CVs
    task_id = hammer.run_async("content-view", "publish", "--name", cv, org=org)
    if not hammer.dry_run:
        logger.info("  Publish task %s started — polling...", task_id)
        poll_task(hammer, task_id, f"Publish '{cv}'", logger)

    after_versions = get_cv_versions(hammer, org, cv)
    after_max_entry = max(after_versions, key=version_sort_key) if after_versions else None
    after_max   = after_max_entry["version"] if after_max_entry else None
    after_count = len(after_versions)
    logger.info("  After:  count=%d  max=%s", after_count, after_max or "<none>")

    if hammer.dry_run:
        logger.info("✔ DRY-RUN publish complete")
        return

    # Verify a new version was actually created
    if before_max and after_max == before_max:
        raise RuntimeError(
            f"Publish did NOT create a new version (max still {after_max}). Aborting."
        )

    if not before_max:
        logger.info("✔ First publish ever — nothing to prune.")
        return

    new_id = after_max_entry["id"]
    logger.info("✔ New version: %s  (id=%s)", after_max, new_id)

    # Promote async — also slow for large CVs
    if do_promote and lifecycle_env:
        logger.info("Promoting id=%s → '%s'", new_id, lifecycle_env)
        task_id = hammer.run_async(
            "content-view", "version", "promote",
            "--id", new_id,
            "--to-lifecycle-environment", lifecycle_env,
            org=org,
        )
        logger.info("  Promote task %s started — polling...", task_id)
        poll_task(hammer, task_id, f"Promote to '{lifecycle_env}'", logger)
        logger.info("✔ Promoted to '%s'", lifecycle_env)

    # Prune — find oldest version that is SAFE to delete:
    #   safe = envs is empty OR envs is exactly "Library"
    if after_count <= min_keep:
        logger.warning("⚠ Only %d version(s) — min_keep=%d. Skipping prune.", after_count, min_keep)
        return

    safe_candidates = [
        v for v in after_versions
        if v["envs"] == "" or v["envs"] == "Library"
    ]
    if not safe_candidates:
        logger.warning("⚠ No SAFE old versions to prune (all are promoted beyond Library).")
        return

    oldest_safe = min(safe_candidates, key=version_sort_key)

    if oldest_safe["id"] == new_id:
        logger.warning("⚠ Oldest safe candidate IS the new version. Refusing to delete.")
        return

    if oldest_safe["envs"] not in ("", "Library"):
        logger.warning("⚠ Candidate id=%s has envs='%s'. Refusing to delete.",
                       oldest_safe["id"], oldest_safe["envs"])
        return

    if after_count - 1 < min_keep:
        logger.warning("⚠ Deletion would drop below min_keep=%d. Skipping.", min_keep)
        return

    # Delete async — also potentially slow
    logger.info("Pruning old version id=%s (envs='%s')",
                oldest_safe["id"], oldest_safe["envs"] or "<none>")
    task_id = hammer.run_async(
        "content-view", "version", "delete", "--id", oldest_safe["id"], org=org
    )
    logger.info("  Delete task %s started — polling...", task_id)
    poll_task(hammer, task_id, f"Delete version {oldest_safe['id']}", logger)
    logger.info("✔ Pruned version id=%s", oldest_safe["id"])


# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------
def run_pipeline(pipeline: Dict, hammer: Hammer, lock_dir: str,
                 logger: logging.Logger) -> bool:
    """
    Run a single pipeline. Returns True on success, False on failure.
    """
    name         = pipeline["name"]
    org          = pipeline.get("org", "Epiq")
    repos        = pipeline.get("repos") or []
    cv           = pipeline["content_view"]
    lifecycle_env = pipeline.get("lifecycle_env", "")
    do_promote   = bool(pipeline.get("do_promote", True))
    min_keep     = int(pipeline.get("min_versions_to_keep", 1))

    logger.info("━" * 52)
    logger.info("Pipeline: %s", name)
    logger.info("━" * 52)

    try:
        with PipelineLock(name, lock_dir):
            # ── 1) Parallel repo sync ──────────────────────────────────
            if not repos:
                logger.warning("⚠ No repos defined — skipping sync phase.")
            else:
                logger.info("Syncing %d repo(s) in parallel...", len(repos))
                results: Dict[str, bool] = {}

                with ThreadPoolExecutor(max_workers=len(repos)) as pool:
                    futures: Dict[Future, str] = {
                        pool.submit(sync_repo, hammer, org,
                                   repo_entry_name(r), repo_entry_product(r), logger): repo_entry_name(r)
                        for r in repos
                    }
                    for future in as_completed(futures):
                        repo_name, ok = future.result()
                        results[repo_name] = ok

                failed_repos = [r for r, ok in results.items() if not ok]
                if failed_repos:
                    logger.error("✘ Sync failed for: %s", ", ".join(failed_repos))
                    logger.error("✘ Aborting pipeline '%s'.", name)
                    return False

                logger.info("✔ All repos synced successfully.")

            # ── 2) Publish + promote + prune ───────────────────────────
            publish_and_prune(hammer, org, cv, lifecycle_env,
                              do_promote, min_keep, logger)

    except RuntimeError as e:
        logger.error("✘ %s", e)
        return False
    except HammerError as e:
        logger.error("✘ Hammer error in pipeline '%s': %s", name, e)
        return False

    logger.info("✔ Pipeline '%s' completed successfully.", name)
    return True


# ---------------------------------------------------------------------------
# List pipelines
# ---------------------------------------------------------------------------
def list_pipelines(pipelines: List[Dict]) -> None:
    print(f"\n{'#':<4}  {'NAME':<30}  {'ORG':<15}  {'CONTENT VIEW':<30}  "
          f"{'LIFECYCLE ENV':<20}  REPOS")
    print("-" * 120)
    for i, p in enumerate(pipelines):
        raw_repos = p.get("repos") or []
        repos_str = ", ".join(repo_entry_name(r) for r in raw_repos) or "(none)"
        print(f"{i:<4}  {p.get('name',''):<30}  {p.get('org',''):<15}  "
              f"{p.get('content_view',''):<30}  "
              f"{p.get('lifecycle_env',''):<20}  {repos_str}")
    print()


# ---------------------------------------------------------------------------
# Config loader + validator
# ---------------------------------------------------------------------------
def load_config(path: str) -> List[Dict]:
    if not os.path.exists(path):
        sys.exit(f"ERROR: Config file not found: {path}")
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        sys.exit(f"ERROR: Invalid YAML in {path}: {e}")

    if not isinstance(data, dict) or "pipelines" not in data:
        sys.exit(f"ERROR: Config file missing 'pipelines' key: {path}")

    pipelines = data["pipelines"]
    if not isinstance(pipelines, list) or len(pipelines) == 0:
        sys.exit(f"ERROR: No pipelines defined in {path}")

    for i, p in enumerate(pipelines):
        if not p.get("name"):
            sys.exit(f"ERROR: Pipeline[{i}] missing 'name'")
        if not p.get("content_view"):
            sys.exit(f"ERROR: Pipeline '{p.get('name', i)}' missing 'content_view'")
        # Warn about repos missing a product — hammer requires it
        for r in (p.get("repos") or []):
            if isinstance(r, dict) and not r.get("product"):
                print(
                    f"WARNING: Pipeline '{p.get('name')}': repo '{r.get('name')}' "
                    f"has no product set. Sync will likely fail.\n"
                    f"         Fix: add 'product: <product name>' to this repo entry in the YAML.",
                    file=sys.stderr,
                )

    return pipelines


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Foreman/Katello Pipeline Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--config",   default=DEFAULT_CONFIG,
                        help=f"Path to pipelines YAML (default: {DEFAULT_CONFIG})")
    parser.add_argument("--pipeline", default="",
                        help="Run only this named pipeline (default: run all)")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Print hammer commands without executing")
    parser.add_argument("--list",     action="store_true",
                        help="List all pipelines and exit")
    args = parser.parse_args()

    logger = setup_logging(DEFAULT_LOG_DIR)

    if args.dry_run:
        logger.warning("⚠ DRY-RUN mode — no changes will be made.")

    # Load config (does its own sys.exit on error)
    pipelines = load_config(args.config)

    if args.list:
        list_pipelines(pipelines)
        return

    # Initialise hammer (validates token + binary)
    try:
        h = Hammer(dry_run=args.dry_run)
    except HammerError as e:
        sys.exit(f"ERROR: {e}")

    # Filter pipelines
    if args.pipeline:
        targets = [p for p in pipelines if p["name"] == args.pipeline]
        if not targets:
            names = ", ".join(p["name"] for p in pipelines)
            sys.exit(
                f"ERROR: No pipeline named '{args.pipeline}' found in {args.config}.\n"
                f"Available: {names}\n"
                f"Use --list to see full details."
            )
    else:
        targets = pipelines

    # Run pipelines sequentially (repos within each pipeline run in parallel)
    succeeded = 0
    failed    = 0

    for pipeline in targets:
        ok = run_pipeline(pipeline, h, DEFAULT_LOCK_DIR, logger)
        if ok:
            succeeded += 1
        else:
            failed += 1
            logger.error("✘ Pipeline '%s' FAILED.", pipeline["name"])

    total = succeeded + failed
    print()
    logger.info("Summary: %d succeeded, %d failed (out of %d run)",
                succeeded, failed, total)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
