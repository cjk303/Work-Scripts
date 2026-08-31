#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Ubuntu CV Publish + Promote + Prune (Katello/Foreman hammer)
#
# What it does:
#   1) Publishes a new version of an existing Content View
#   2) Optionally promotes that new version to a lifecycle environment
#   3) Deletes the oldest SAFE version only if a new version was successfully created
#
# Safety rules:
#   - NEVER delete if total versions <= MIN_VERSIONS_TO_KEEP (default: 1)
#   - NEVER delete anything promoted beyond Library (e.g. "Library, Ubuntu 24.04")
#   - Only delete versions with lifecycle env column either:
#       a) empty, OR
#       b) exactly "Library"
###############################################################################

die() { echo "ERROR: $*" >&2; exit 1; }
log() { echo "==> $*"; }

# ----------------------------
# Config (override via env)
# ----------------------------
ORG="${ORG:-Epiq}"
CV_NAME="${CV_NAME:-Ubuntu 24.04}"
LIFECYCLE_ENV="${LIFECYCLE_ENV:-Ubuntu 24.04}"

HAMMER_USER="${HAMMER_USER:-admin}"
HAMMER_TOKEN="${HAMMER_TOKEN:-}"

# Optional: set FOREMAN_SERVER if hammer isn't already configured
# Example: export FOREMAN_SERVER="https://p054lnxfore01.epiqcorp.com"
FOREMAN_SERVER="${FOREMAN_SERVER:-}"

# Promote new version? true/false
DO_PROMOTE="${DO_PROMOTE:-true}"

# Keep at least this many versions; script will NEVER delete if versions <= this number.
MIN_VERSIONS_TO_KEEP="${MIN_VERSIONS_TO_KEEP:-1}"

# Optional: dry run
DRY_RUN="${DRY_RUN:-false}"

# Optional: lock to prevent concurrent cron runs
LOCKFILE="${LOCKFILE:-/var/lock/ubuntu_publish_${ORG// /_}_${CV_NAME// /_}.lock}"

# ----------------------------
# Sanity checks
# ----------------------------
command -v hammer >/dev/null 2>&1 || die "hammer CLI not found"
[[ -n "$HAMMER_TOKEN" ]] || die "HAMMER_TOKEN is not set (export HAMMER_TOKEN='1-xxxxx')"

# ----------------------------
# Lock (best effort)
# ----------------------------
acquire_lock() {
  if command -v flock >/dev/null 2>&1; then
    exec 200>"$LOCKFILE"
    flock -n 200 || die "Another instance is running (lock: $LOCKFILE)"
  else
    mkdir "${LOCKFILE}.d" 2>/dev/null || die "Another instance is running (lockdir: ${LOCKFILE}.d)"
    trap 'rmdir "${LOCKFILE}.d" 2>/dev/null || true' EXIT
  fi
}

# ----------------------------
# Hammer wrapper (NO global --organization!)
# Your hammer rejects --organization globally, so we never put it here.
# ----------------------------
h() {
  local args=(--username "$HAMMER_USER" --password "$HAMMER_TOKEN")
  [[ -n "$FOREMAN_SERVER" ]] && args+=(--server "$FOREMAN_SERVER")
  if [[ "$DRY_RUN" == "true" ]]; then
    log "DRY_RUN: hammer ${args[*]} $*"
    return 0
  fi
  hammer "${args[@]}" "$@"
}

# Some subcommands accept --organization, some don't.
# We'll try with --organization at the end; if hammer says unrecognised, retry without.
h_org() {
  set +e
  local out rc
  out="$(h "$@" --organization "$ORG" 2>&1)"
  rc=$?
  set -e

  if (( rc == 0 )); then
    printf "%s\n" "$out"
    return 0
  fi

  if echo "$out" | grep -qi "Unrecognised option '--organization'"; then
    # retry without --organization
    h "$@"
    return 0
  fi

  # real error
  echo "$out" >&2
  return "$rc"
}

# ----------------------------
# Parse versions: ID|VERSION|ENVS
# ----------------------------
list_versions() {
  h_org content-view version list --content-view "$CV_NAME" \
  | awk -F'|' '
      $0 ~ /^----/ { next }
      $0 ~ /^[[:space:]]*ID[[:space:]]*\|/ { next }
      NF < 5 { next }
      {
        id=$1; ver=$3; env=$5
        gsub(/^[ \t]+|[ \t]+$/, "", id)
        gsub(/^[ \t]+|[ \t]+$/, "", ver)
        gsub(/^[ \t]+|[ \t]+$/, "", env)
        if (id ~ /^[0-9]+$/ && ver != "") print id "|" ver "|" env
      }'
}

count_versions() { list_versions | wc -l | tr -d ' '; }
max_version() { list_versions | cut -d'|' -f2 | sort -V | tail -n1; }

id_for_version() {
  local v="$1"
  list_versions | awk -F'|' -v want="$v" '$2==want {print $1; exit}'
}

# Oldest SAFE deletable version:
# - env column empty OR exactly "Library"
oldest_safe_id() {
  list_versions \
    | awk -F'|' '$3=="" || $3=="Library"' \
    | sort -t'|' -k2,2V \
    | head -n1 \
    | cut -d'|' -f1
}

envs_for_id() {
  local id="$1"
  list_versions | awk -F'|' -v i="$id" '$1==i {print $3; exit}'
}

# ----------------------------
# Main
# ----------------------------
acquire_lock

log "Publishing Content View: '$CV_NAME' (org='$ORG')"
before_count="$(count_versions || true)"
before_max="$(max_version || true)"
log "Before: count=$before_count max=${before_max:-<none>}"

# Publish new version
h_org content-view publish --name "$CV_NAME" >/dev/null

after_count="$(count_versions)"
after_max="$(max_version)"
log "After:  count=$after_count max=${after_max:-<none>}"

# Confirm new version exists
if [[ -n "${before_max:-}" && "$after_max" == "$before_max" ]]; then
  die "Publish did NOT create a new version (max unchanged: $after_max). Will NOT delete anything."
fi

# If it was first publish ever, do not delete
if [[ -z "${before_max:-}" ]]; then
  log "First publish detected. Will NOT delete anything."
  exit 0
fi

new_id="$(id_for_version "$after_max")"
[[ -n "$new_id" ]] || die "Could not determine new version ID for version '$after_max'"
log "New version created: version=$after_max id=$new_id"

# Promote (optional)
if [[ "${DO_PROMOTE,,}" == "true" ]]; then
  log "Promoting id=$new_id to lifecycle environment '$LIFECYCLE_ENV'"
  h_org content-view version promote --id "$new_id" --to-lifecycle-environment "$LIFECYCLE_ENV" >/dev/null
fi

# Never delete if only one (or <= MIN_VERSIONS_TO_KEEP)
if (( after_count <= MIN_VERSIONS_TO_KEEP )); then
  log "Safety: only $after_count version(s) exist (min keep=$MIN_VERSIONS_TO_KEEP). Nothing will be deleted."
  exit 0
fi

old_id="$(oldest_safe_id || true)"
if [[ -z "${old_id:-}" ]]; then
  log "No SAFE old versions found (only promoted versions exist). Nothing will be deleted."
  exit 0
fi

# Paranoia: never delete the new version
if [[ "$old_id" == "$new_id" ]]; then
  log "Oldest safe candidate is the new version itself; refusing to delete."
  exit 0
fi

cand_env="$(envs_for_id "$old_id" || true)"
# Paranoia: never delete anything promoted beyond Library
if [[ -n "$cand_env" && "$cand_env" != "Library" ]]; then
  log "Safety: candidate id=$old_id has envs='$cand_env' (non-Library). Refusing to delete."
  exit 0
fi

# Final safety: do not delete below threshold
if (( after_count - 1 < MIN_VERSIONS_TO_KEEP )); then
  log "Safety: deletion would drop versions below min keep=$MIN_VERSIONS_TO_KEEP. Refusing to delete."
  exit 0
fi

log "Deleting oldest SAFE version id=$old_id (envs='${cand_env:-<none>}')"
h_org content-view version delete --id "$old_id" >/dev/null

log "Done. Remaining versions:"
list_versions | sort -t'|' -k2,2V

