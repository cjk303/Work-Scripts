#!/usr/bin/env bash
set -euo pipefail

# Azure Arc Connected Machine Agent repair helper
# Fixes common service-account + permissions issues for:
#  - himdsd (User=himds/Group=himds)
#  - arcproxyd (Arc Proxy runs as arcproxy user on Linux)  [1](https://learn.microsoft.com/en-us/azure/azure-arc/servers/agent-overview)
# Then restarts services and runs basic diagnostics:
#  - azcmagent show
#  - azcmagent check (network connectivity checks)          [2](https://learn.microsoft.com/en-us/azure/azure-arc/servers/azcmagent-check)[3](https://docs.azure.cn/en-us/azure-arc/servers/azcmagent)

LOG_PREFIX="[arc-repair]"
AZC_DIR="/var/opt/azcmagent"
AZC_LOG_DIR="/var/opt/azcmagent/log"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "${LOG_PREFIX} ERROR: must be run as root." >&2
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

msg() { echo "${LOG_PREFIX} $*"; }

ensure_group() {
  local grp="$1"
  if getent group "${grp}" >/dev/null 2>&1; then
    msg "Group '${grp}' exists."
  else
    msg "Creating system group '${grp}'..."
    groupadd --system "${grp}"
  fi
}

ensure_user() {
  local usr="$1" grp="$2"
  if getent passwd "${usr}" >/dev/null 2>&1; then
    msg "User '${usr}' exists."
  else
    msg "Creating system user '${usr}' (group '${grp}', nologin, no home)..."
    # Create as a system user with no login and no home directory
    useradd --system --no-create-home --shell /usr/sbin/nologin --gid "${grp}" "${usr}"
  fi
}

service_user_from_unit() {
  local unit="$1"
  # Returns user configured for a systemd unit (may be empty)
  systemctl show "${unit}" -p User --value 2>/dev/null || true
}

service_group_from_unit() {
  local unit="$1"
  systemctl show "${unit}" -p Group --value 2>/dev/null || true
}

unit_exists() {
  systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "$1"
}

restart_unit() {
  local unit="$1"
  if unit_exists "${unit}"; then
    msg "Restarting ${unit}..."
    systemctl reset-failed "${unit}" >/dev/null 2>&1 || true
    systemctl restart "${unit}"
  else
    msg "Unit ${unit} not found; skipping."
  fi
}

show_unit_status() {
  local unit="$1"
  if unit_exists "${unit}"; then
    msg "Status for ${unit}:"
    systemctl --no-pager -l status "${unit}" || true
  fi
}

tail_logs_if_present() {
  local file="$1"
  if [[ -f "$file" ]]; then
    msg "Last 120 lines of $file:"
    tail -n 120 "$file" || true
  fi
}

main() {
  require_root

  msg "Starting Azure Arc agent repair..."

  # 1) Ensure required service accounts exist.
  # himdsd.service uses User=himds Group=himds (as you observed).
  # arcproxyd runs as arcproxy on Linux (Arc Proxy component) [1](https://learn.microsoft.com/en-us/azure/azure-arc/servers/agent-overview)
  for acct in himds arcproxy; do
    ensure_group "${acct}"
    ensure_user  "${acct}" "${acct}"
  done

  # 2) Ensure baseline ownership for Arc state directory.
  # Use conservative ownership:
  # - Keep top dir root-owned but readable
  # - Ensure sockets/log/state is owned by service accounts as needed
  if [[ -d "${AZC_DIR}" ]]; then
    msg "Setting safe permissions on ${AZC_DIR}..."
    chmod 0755 "${AZC_DIR}" || true

    # Ownership hints:
    # HIMDS primarily uses /var/opt/azcmagent (logs/socks/state).
    # We'll ensure both service accounts can manage their paths.
    # Make log dir readable and files writable by their owning service.
    if [[ -d "${AZC_LOG_DIR}" ]]; then
      chmod 0755 "${AZC_LOG_DIR}" || true
    fi

    # Ensure full tree is at least accessible; fix ownership for known subdirs
    for sub in socks state config log; do
      if [[ -d "${AZC_DIR}/${sub}" ]]; then
        msg "Adjusting ownership for ${AZC_DIR}/${sub}..."
        # Prefer himds ownership for core dirs; proxy will create/use its own files
        chown -R himds:himds "${AZC_DIR}/${sub}" 2>/dev/null || true
        chmod -R u+rwX,go-rwx "${AZC_DIR}/${sub}" 2>/dev/null || true
      fi
    done

    # Allow arcproxy to own its own logs if present
    for f in arcproxy.log arcproxyd.log; do
      if [[ -f "${AZC_LOG_DIR}/${f}" ]]; then
        chown arcproxy:arcproxy "${AZC_LOG_DIR}/${f}" 2>/dev/null || true
      fi
    done
  else
    msg "WARN: ${AZC_DIR} not found. Is azcmagent installed?"
  fi

  # 3) Restart services in dependency-ish order:
  # HIMDS first, then proxy, then others.
  restart_unit "himdsd.service"
  restart_unit "arcproxyd.service"
  restart_unit "extd.service"
  restart_unit "gcad.service"

  # 4) Show status summary
  show_unit_status "himdsd.service"
  show_unit_status "arcproxyd.service"
  show_unit_status "extd.service"
  show_unit_status "gcad.service"

  # 5) If arcproxyd still not running, show its journal/log quickly.
  if unit_exists "arcproxyd.service"; then
    if ! systemctl is-active --quiet arcproxyd.service; then
      msg "arcproxyd is not active; dumping recent journal..."
      journalctl -u arcproxyd.service -n 120 --no-pager || true
      tail_logs_if_present "${AZC_LOG_DIR}/arcproxy.log"
    fi
  fi

  # 6) Run azcmagent diagnostics if available:
  if have_cmd azcmagent; then
    msg "Running: azcmagent show"
    azcmagent show || true

    msg "Running: azcmagent check (connectivity checks for required endpoints)"  # [2](https://learn.microsoft.com/en-us/azure/azure-arc/servers/azcmagent-check)[3](https://docs.azure.cn/en-us/azure-arc/servers/azcmagent)
    azcmagent check || true
  else
    msg "WARN: azcmagent CLI not found in PATH."
  fi

  msg "Repair complete."
}

main "$@"
