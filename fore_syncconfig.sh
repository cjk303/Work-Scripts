#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Foreman Pipeline Config Generator
#
# Interactive TUI to build pipelines.yaml by browsing live Foreman data.
# Requires: hammer, dialog (or whiptail as fallback)
#
# Usage:
#   foreman_config_gen.sh [--output FILE] [--server URL]
#
# Env vars:
#   HAMMER_TOKEN     required
#   HAMMER_USER      default: admin
#   FOREMAN_SERVER   optional if hammer.yml already configured
#   OUTPUT_FILE      default: ./pipelines.yaml
###############################################################################

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
HAMMER_USER="${HAMMER_USER:-admin}"
HAMMER_TOKEN="${HAMMER_TOKEN:-}"
FOREMAN_SERVER="${FOREMAN_SERVER:-}"
OUTPUT_FILE="${OUTPUT_FILE:-./pipelines.yaml}"

DLG_H=30
DLG_W=80
DLG_LIST_H=20

# ---------------------------------------------------------------------------
# Arg parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output|-o)  shift; OUTPUT_FILE="$1" ;;
    --server|-s)  shift; FOREMAN_SERVER="$1" ;;
    --help|-h)
      echo "Usage: $0 [--output FILE] [--server URL]"
      echo "Env: HAMMER_TOKEN, HAMMER_USER, FOREMAN_SERVER"
      exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
die()  { clear; echo "ERROR: $*" >&2; exit 1; }

check_deps() {
  local missing=()
  command -v hammer >/dev/null 2>&1 || missing+=(hammer)
  (( ${#missing[@]} == 0 )) || die "Missing required tools: ${missing[*]}"
  [[ -n "$HAMMER_TOKEN" ]] || die "HAMMER_TOKEN is not set"
}

# Pick dialog backend
if command -v dialog >/dev/null 2>&1; then
  DIALOG=dialog
elif command -v whiptail >/dev/null 2>&1; then
  DIALOG=whiptail
else
  die "Neither 'dialog' nor 'whiptail' found. Install: apt install dialog"
fi

# ---------------------------------------------------------------------------
# Hammer wrapper
# ---------------------------------------------------------------------------
h() {
  local args=(--username "$HAMMER_USER" --password "$HAMMER_TOKEN")
  [[ -n "$FOREMAN_SERVER" ]] && args+=(--server "$FOREMAN_SERVER")
  hammer "${args[@]}" "$@"
}

h_org() {
  local org="$1"; shift
  set +e
  local out rc
  out="$(h "$@" --organization "$org" 2>&1)"
  rc=$?
  set -e
  if (( rc == 0 )); then printf "%s\n" "$out"; return 0; fi
  if echo "$out" | grep -qi "Unrecognised option '--organization'"; then
    h "$@"; return 0
  fi
  echo "$out" >&2
  return "$rc"
}

# ---------------------------------------------------------------------------
# Data fetchers
#
# parse_name_col: finds the NAME column dynamically from the hammer header
# row, so it works regardless of column count or order.
# Optional arg: a single value to exclude (e.g. "Library").
# ---------------------------------------------------------------------------
parse_name_col() {
  local exclude="${1:-__NO_EXCLUDE__}"
  awk -F'|' -v exclude="$exclude" '
    /^[- |]+$/  { next }
    !col && /NAME/ {
      for (i=1; i<=NF; i++) {
        v=$i; gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
        if (v == "NAME") { col=i; break }
      }
      next
    }
    col && NF >= col {
      v=$col; gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
      if (v != "" && v != exclude) print v
    }
  '
}

fetch_orgs() {
  h organization list | parse_name_col
}

fetch_products() {
  local org="$1"
  h_org "$org" product list | parse_name_col
}

fetch_repos() {
  local org="$1" product="$2"
  h_org "$org" repository list --product "$product" | parse_name_col
}

fetch_content_views() {
  local org="$1"
  h_org "$org" content-view list | parse_name_col "Default Organization View"
}

fetch_lifecycle_envs() {
  local org="$1"
  h_org "$org" lifecycle-environment list | parse_name_col "Library"
}

# ---------------------------------------------------------------------------
# Dialog helpers
#
# KEY DESIGN: dialog writes its user selection to stderr. We redirect stderr
# to a dedicated temp file (_DLG_TMP) and read from it. This means dialog's
# terminal control/escape sequences NEVER touch stdout, so subshell captures
# of build_pipeline stay clean and the YAML is never corrupted.
# ---------------------------------------------------------------------------
_DLG_TMP="$(mktemp)"
trap 'rm -f "$_DLG_TMP"' EXIT

_dlg() {
  : >"$_DLG_TMP"
  $DIALOG "$@" 2>"$_DLG_TMP"
}

# Radio list — prints the single selected item on stdout
dlg_radio() {
  local title="$1" prompt="$2"; shift 2
  local items=() first=true
  for item in "$@"; do
    if $first; then items+=("$item" "" on); first=false
    else             items+=("$item" "" off)
    fi
  done
  _dlg --title "$title" --radiolist "$prompt" \
    $DLG_H $DLG_W $DLG_LIST_H "${items[@]}" || return 1
  cat "$_DLG_TMP"
}

# Checklist — prints dialog's raw output (quoted tokens) on stdout
dlg_check() {
  local title="$1" prompt="$2"; shift 2
  local items=()
  for item in "$@"; do
    items+=("$item" "" off)
  done
  _dlg --title "$title" \
    --checklist "$prompt  (SPACE=select, multiple allowed)" \
    $DLG_H $DLG_W $DLG_LIST_H "${items[@]}" || return 1
  cat "$_DLG_TMP"
}

# Input box — prints entered text on stdout
dlg_input() {
  local title="$1" prompt="$2" default="${3:-}"
  _dlg --title "$title" --inputbox "$prompt" 10 $DLG_W "$default" || return 1
  cat "$_DLG_TMP"
}

# Yes/No — prints "true" or "false", never fails
dlg_yesno() {
  local title="$1" prompt="$2"
  if _dlg --title "$title" --yesno "$prompt" 8 $DLG_W; then
    echo "true"
  else
    echo "false"
  fi
}

# Message box — blocks until OK, no stdout output
dlg_msg() {
  local title="$1" msg="$2"
  $DIALOG --title "$title" --msgbox "$msg" $DLG_H $DLG_W || true
}

# Info box — non-blocking status, written direct to terminal (not captured)
dlg_info() {
  $DIALOG --title "Please wait" --infobox "$1" 5 60 || true
}

# Main menu — prints chosen tag on stdout
dlg_menu() {
  local title="$1" prompt="$2"; shift 2
  _dlg --title "$title" --menu "$prompt" 15 $DLG_W 6 "$@" || return 1
  cat "$_DLG_TMP"
}

# ---------------------------------------------------------------------------
# Pipeline builder
# All dialog calls go through the helpers above — nothing touches stdout
# except the final echo statements that produce the YAML block.
# ---------------------------------------------------------------------------
build_pipeline() {
  # Step 1 — pipeline name
  local pipe_name
  pipe_name="$(dlg_input "Pipeline Name" \
    "Enter a unique name for this pipeline (e.g. ubuntu-24.04):" "")" || return 1
  [[ -n "$pipe_name" ]] || { dlg_msg "Error" "Pipeline name cannot be empty."; return 1; }

  # Step 2 — organisation
  dlg_info "Loading organisations from Foreman..."
  local orgs_raw
  orgs_raw="$(fetch_orgs 2>/dev/null)" || { dlg_msg "Error" "Failed to fetch organisations."; return 1; }
  [[ -n "$orgs_raw" ]] || { dlg_msg "Error" "No organisations found in Foreman."; return 1; }
  mapfile -t orgs <<<"$orgs_raw"

  local org
  org="$(dlg_radio "Organisation" "Select organisation:" "${orgs[@]}")" || return 1

  # Step 3 — products + repos (loop to allow multiple products)
  local all_repos=()
  local add_more=true

  while $add_more; do
    dlg_info "Loading products for '$org'..."
    local prods_raw
    prods_raw="$(fetch_products "$org" 2>/dev/null)" \
      || { dlg_msg "Error" "Failed to fetch products for '$org'."; return 1; }
    [[ -n "$prods_raw" ]] || { dlg_msg "Error" "No products found for '$org'."; return 1; }
    mapfile -t prods <<<"$prods_raw"

    local product
    product="$(dlg_radio "Product" "Select a product to browse repositories:" \
      "${prods[@]}")" || break

    dlg_info "Loading repositories for '$product'..."
    local repos_raw
    repos_raw="$(fetch_repos "$org" "$product" 2>/dev/null)" \
      || { dlg_msg "Error" "Failed to fetch repos for '$product'."; continue; }
    [[ -n "$repos_raw" ]] || { dlg_msg "Warning" "No repositories found for '$product'."; continue; }
    mapfile -t repos <<<"$repos_raw"

    local selected_raw
    selected_raw="$(dlg_check "Repositories" \
      "Select repos from '$product' for this pipeline:" \
      "${repos[@]}")" || continue

    # dialog quotes items containing spaces: "My Repo" "Other Repo"
    # eval splits them correctly into array elements
    if [[ -n "$selected_raw" ]]; then
      local tmp_arr=()
      eval "tmp_arr=($selected_raw)"
      all_repos+=("${tmp_arr[@]}")
    fi

    local more
    more="$(dlg_yesno "More Products?" \
      "Add repositories from another product to this pipeline?")"
    [[ "$more" == "true" ]] || add_more=false
  done

  (( ${#all_repos[@]} > 0 )) \
    || dlg_msg "Warning" "No repositories selected — pipeline will skip the sync phase."

  # Step 4 — content view
  dlg_info "Loading content views for '$org'..."
  local cvs_raw
  cvs_raw="$(fetch_content_views "$org" 2>/dev/null)" \
    || { dlg_msg "Error" "Failed to fetch content views."; return 1; }
  [[ -n "$cvs_raw" ]] || { dlg_msg "Error" "No content views found for '$org'."; return 1; }
  mapfile -t cvs <<<"$cvs_raw"

  local cv
  cv="$(dlg_radio "Content View" "Select the Content View to publish:" \
    "${cvs[@]}")" || return 1

  # Step 5 — promote?
  local do_promote lifecycle_env=""
  do_promote="$(dlg_yesno "Promote?" \
    "Promote the new Content View version after publishing?")"

  if [[ "$do_promote" == "true" ]]; then
    dlg_info "Loading lifecycle environments for '$org'..."
    local lcs_raw
    lcs_raw="$(fetch_lifecycle_envs "$org" 2>/dev/null)" || true

    if [[ -z "$lcs_raw" ]]; then
      dlg_msg "Warning" "No lifecycle environments found (besides Library). Disabling promotion."
      do_promote=false
    else
      mapfile -t lcs <<<"$lcs_raw"
      lifecycle_env="$(dlg_radio "Lifecycle Environment" \
        "Select target lifecycle environment:" "${lcs[@]}")" || do_promote=false
    fi
  fi

  # Step 6 — version retention
  local min_keep
  min_keep="$(dlg_input "Version Retention" \
    "Minimum Content View versions to keep before pruning old ones:" "1")" \
    || min_keep=1
  [[ "$min_keep" =~ ^[0-9]+$ ]] || min_keep=1

  # Emit clean YAML — only echo statements here, no printf %b, no escape sequences
  echo "  - name: ${pipe_name}"
  echo "    org: ${org}"
  if (( ${#all_repos[@]} > 0 )); then
    echo "    repos:"
    for repo in "${all_repos[@]}"; do
      echo "      - \"${repo}\""
    done
  else
    echo "    repos: []"
  fi
  echo "    content_view: \"${cv}\""
  echo "    lifecycle_env: \"${lifecycle_env}\""
  echo "    do_promote: ${do_promote}"
  echo "    min_versions_to_keep: ${min_keep}"
}

# ---------------------------------------------------------------------------
# Load existing pipelines (pipeline entries only, header stripped)
# ---------------------------------------------------------------------------
load_existing() {
  [[ -f "$OUTPUT_FILE" ]] || return 0
  awk '/^  - name:/{found=1} found{print}' "$OUTPUT_FILE"
}

# ---------------------------------------------------------------------------
# Write config atomically (tmp file + mv, never leaves partial file on crash)
# ---------------------------------------------------------------------------
write_config() {
  local pipelines_yaml="$1"
  local tmp
  tmp="$(mktemp "$(dirname "$OUTPUT_FILE")/.pipelines_tmp.XXXXXX")"

  {
    echo "---"
    echo "# Foreman Pipeline Config"
    echo "# Generated by foreman_config_gen.sh on $(date '+%Y-%m-%d %H:%M:%S')"
    echo "#"
    echo "# Run all:  HAMMER_TOKEN=xxx foreman_pipeline.sh --config ${OUTPUT_FILE}"
    echo "# Run one:  HAMMER_TOKEN=xxx foreman_pipeline.sh --config ${OUTPUT_FILE} --pipeline NAME"
    echo ""
    echo "pipelines:"
    printf "%s\n" "$pipelines_yaml"
  } >"$tmp"

  mv "$tmp" "$OUTPUT_FILE"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  check_deps

  clear
  dlg_msg "Foreman Pipeline Config Generator" \
"Welcome!

This tool guides you through creating pipelines.yaml
for use with foreman_pipeline.sh.

Output file: ${OUTPUT_FILE}"

  local all_pipelines=""

  # Offer to load existing config
  if [[ -f "$OUTPUT_FILE" ]]; then
    local load_choice
    load_choice="$(dlg_yesno "Existing Config Found" \
      "Found: ${OUTPUT_FILE}

Load existing pipelines and add to them?")"
    if [[ "$load_choice" == "true" ]]; then
      all_pipelines="$(load_existing)"
      local cnt
      cnt="$(echo "$all_pipelines" | grep -c '^\s*- name:' || true)"
      dlg_msg "Loaded" "Loaded ${cnt} existing pipeline(s)."
    fi
  fi

  local keep_going=true
  while $keep_going; do
    local choice
    choice="$(dlg_menu "Main Menu" "What would you like to do?" \
      "add"    "Add a new pipeline" \
      "review" "Review pipelines defined so far" \
      "save"   "Save config and exit" \
      "quit"   "Quit without saving")" || { keep_going=false; break; }

    case "$choice" in
      add)
        local new_pipeline
        new_pipeline="$(build_pipeline)" || {
          dlg_msg "Cancelled" "Pipeline creation was cancelled."
          continue
        }
        if [[ -n "$new_pipeline" ]]; then
          if [[ -n "$all_pipelines" ]]; then
            all_pipelines="${all_pipelines}"$'\n'"${new_pipeline}"
          else
            all_pipelines="$new_pipeline"
          fi
          local names
          names="$(echo "$all_pipelines" | grep '^\s*- name:' | sed 's/.*name:[[:space:]]*/  • /')"
          dlg_msg "Added" "Pipeline added!

Current pipelines:
${names}"
        fi
        ;;

      review)
        if [[ -z "$all_pipelines" ]]; then
          dlg_msg "Review" "No pipelines defined yet."
        else
          local names
          names="$(echo "$all_pipelines" | grep '^\s*- name:' | sed 's/.*name:[[:space:]]*/  • /')"
          dlg_msg "Current Pipelines" "Pipelines defined so far:

${names}"
        fi
        ;;

      save)
        if [[ -z "$all_pipelines" ]]; then
          local confirm_empty
          confirm_empty="$(dlg_yesno "Save Empty Config?" \
            "No pipelines defined. Save an empty config anyway?")"
          [[ "$confirm_empty" == "false" ]] && continue
        fi
        write_config "$all_pipelines"
        dlg_msg "Saved" "Config written to:
${OUTPUT_FILE}

Run with:
  HAMMER_TOKEN=xxx foreman_pipeline.sh --config ${OUTPUT_FILE}"
        keep_going=false
        ;;

      quit)
        local confirm_quit
        confirm_quit="$(dlg_yesno "Quit" "Quit without saving?")"
        [[ "$confirm_quit" == "true" ]] && keep_going=false
        ;;
    esac
  done

  clear
  if [[ -f "$OUTPUT_FILE" ]] && grep -q '^\s*- name:' "$OUTPUT_FILE" 2>/dev/null; then
    echo "Config saved to: $OUTPUT_FILE"
    echo ""
    echo "Run all pipelines:"
    echo "  HAMMER_TOKEN=xxx foreman_pipeline.sh --config $OUTPUT_FILE"
    echo ""
    echo "Run a single pipeline:"
    echo "  HAMMER_TOKEN=xxx foreman_pipeline.sh --config $OUTPUT_FILE --pipeline NAME"
  else
    echo "Exited without saving."
  fi
}

main
