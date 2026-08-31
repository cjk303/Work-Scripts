#!/usr/bin/env python3
"""
Foreman Pipeline Config Generator

Interactively builds pipelines.yaml by querying live Foreman/Katello
data via the hammer CLI.

Requirements:
    pip install questionary pyyaml

Usage:
    export HAMMER_TOKEN="1-xxxxx"
    export FOREMAN_SERVER="https://your-foreman.example.com"  # optional
    python3 foreman_config_gen.py [--output pipelines.yaml]
"""

import argparse
import datetime
import os
import re
import subprocess
import sys
import tempfile
from typing import Optional, List, Dict, Any

try:
    import questionary
    from questionary import Style
except ImportError:
    sys.exit("Missing dependency: pip install questionary")

try:
    import yaml
except ImportError:
    sys.exit("Missing dependency: pip install pyyaml")


# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------
STYLE = Style([
    ("qmark",        "fg:#00bcd4 bold"),
    ("question",     "fg:#ffffff bold"),
    ("answer",       "fg:#00e676 bold"),
    ("pointer",      "fg:#00bcd4 bold"),
    ("highlighted",  "fg:#00bcd4 bold"),
    ("selected",     "fg:#00e676"),
    ("separator",    "fg:#444444"),
    ("instruction",  "fg:#888888"),
    ("text",         "fg:#cccccc"),
    ("disabled",     "fg:#555555 italic"),
])


# ---------------------------------------------------------------------------
# Hammer wrapper
# ---------------------------------------------------------------------------
class HammerError(Exception):
    pass


def hammer(*args, org: str = None) -> str:
    """
    Run a hammer command and return stdout as a string.
    Automatically injects credentials and optional --server / --organization.
    """
    user  = os.environ.get("HAMMER_USER", "admin")
    token = os.environ.get("HAMMER_TOKEN", "")
    server = os.environ.get("FOREMAN_SERVER", "")

    if not token:
        raise HammerError("HAMMER_TOKEN is not set")

    cmd = ["hammer", "--username", user, "--password", token]
    if server:
        cmd += ["--server", server]

    cmd += list(args)
    if org:
        cmd += ["--organization", org]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        raise HammerError("hammer CLI not found — is it installed and on PATH?")
    except subprocess.TimeoutExpired:
        raise HammerError(f"hammer timed out running: {' '.join(args)}")

    # Some hammer subcommands reject --organization; retry without it
    if org and result.returncode != 0 and "unrecognised option" in result.stderr.lower():
        return hammer(*args)

    if result.returncode != 0:
        raise HammerError(result.stderr.strip() or result.stdout.strip())

    return result.stdout


# ---------------------------------------------------------------------------
# Table parser
# ---------------------------------------------------------------------------
def parse_name_column(raw: str, exclude: List[str] = None) -> List[str]:
    """
    Parse hammer's pipe-delimited tabular output and return values from the
    NAME column. Finds the column index dynamically from the header row so it
    works regardless of how many columns or what order hammer returns them.
    """
    exclude = set(exclude or [])
    col_index = None
    results = []

    for line in raw.splitlines():
        # Skip separator lines like ---|---|---
        if re.match(r'^[\s\-|]+$', line):
            continue

        parts = [p.strip() for p in line.split("|")]
        parts = [p for p in parts if p != ""]

        # Find header
        if col_index is None:
            if "NAME" in parts:
                col_index = parts.index("NAME")
            continue

        if len(parts) > col_index:
            val = parts[col_index]
            if val and val not in exclude:
                results.append(val)

    return results


# ---------------------------------------------------------------------------
# Data fetchers
# ---------------------------------------------------------------------------
def fetch_orgs() -> List[str]:
    return parse_name_column(hammer("organization", "list"))


def fetch_products(org: str) -> List[str]:
    return parse_name_column(hammer("product", "list", org=org))


def fetch_repos(org: str, product: str) -> List[str]:
    return parse_name_column(
        hammer("repository", "list", "--product", product, org=org)
    )


def fetch_content_views(org: str) -> List[str]:
    return parse_name_column(
        hammer("content-view", "list", org=org),
        exclude=["Default Organization View"],
    )


def fetch_lifecycle_envs(org: str) -> List[str]:
    return parse_name_column(
        hammer("lifecycle-environment", "list", org=org),
        exclude=["Library"],
    )


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------
def header(text: str):
    width = 60
    print()
    print("─" * width)
    print(f"  {text}")
    print("─" * width)


def fetching(msg: str):
    print(f"\n  ⟳  {msg}", end="", flush=True)


def fetching_done():
    print(" done.")


def abort(msg: str):
    print(f"\n  ✘  {msg}")
    return None


# ---------------------------------------------------------------------------
# Pipeline builder
# ---------------------------------------------------------------------------
def build_pipeline() -> Optional[dict]:
    header("New Pipeline")

    # Step 1 — name
    name = questionary.text(
        "Pipeline name:",
        instruction="(e.g. ubuntu-24.04)",
        style=STYLE,
    ).ask()
    if not name:
        return None
    name = name.strip()
    if not name:
        print("  Pipeline name cannot be empty.")
        return None

    # Step 2 — organisation
    fetching("Loading organisations...")
    try:
        orgs = fetch_orgs()
        fetching_done()
    except HammerError as e:
        return abort(f"Failed to fetch organisations: {e}")

    if not orgs:
        return abort("No organisations found in Foreman.")

    org = questionary.select(
        "Organisation:",
        choices=orgs,
        style=STYLE,
    ).ask()
    if org is None:
        return None

    # Step 3 — products + repos (loop for multiple products)
    # Repos stored as {name, product} so runner can pass --product to hammer
    all_repos: List[Dict] = []

    while True:
        fetching(f"Loading products for '{org}'...")
        try:
            products = fetch_products(org)
            fetching_done()
        except HammerError as e:
            abort(f"Failed to fetch products: {e}")
            break

        if not products:
            abort(f"No products found for '{org}'.")
            break

        product = questionary.select(
            "Product:",
            choices=products,
            style=STYLE,
        ).ask()
        if product is None:
            break

        fetching(f"Loading repositories for '{product}'...")
        try:
            repos = fetch_repos(org, product)
            fetching_done()
        except HammerError as e:
            abort(f"Failed to fetch repos: {e}")
        else:
            if not repos:
                print(f"  No repositories found for '{product}'.")
            else:
                selected = questionary.checkbox(
                    f"Select repositories from '{product}':",
                    choices=repos,
                    style=STYLE,
                    instruction="(space to select, enter to confirm)",
                ).ask()
                if selected:
                    for repo_name in selected:
                        all_repos.append({"name": repo_name, "product": product})

        add_more = questionary.confirm(
            "Add repositories from another product?",
            default=False,
            style=STYLE,
        ).ask()
        if not add_more:
            break

    if not all_repos:
        print("  ⚠  No repositories selected — pipeline will skip the sync phase.")

    # Step 4 — content view
    fetching(f"Loading content views for '{org}'...")
    try:
        cvs = fetch_content_views(org)
        fetching_done()
    except HammerError as e:
        return abort(f"Failed to fetch content views: {e}")

    if not cvs:
        return abort("No content views found.")

    cv = questionary.select(
        "Content View to publish:",
        choices=cvs,
        style=STYLE,
    ).ask()
    if cv is None:
        return None

    # Step 5 — promote?
    do_promote = questionary.confirm(
        "Promote after publishing?",
        default=True,
        style=STYLE,
    ).ask()

    lifecycle_env = ""
    if do_promote:
        fetching(f"Loading lifecycle environments for '{org}'...")
        try:
            lcs = fetch_lifecycle_envs(org)
            fetching_done()
        except HammerError as e:
            abort(f"Failed to fetch lifecycle environments: {e}")
            do_promote = False

        if do_promote and not lcs:
            print("  ⚠  No lifecycle environments found (besides Library). Disabling promotion.")
            do_promote = False

        if do_promote:
            lifecycle_env = questionary.select(
                "Target lifecycle environment:",
                choices=lcs,
                style=STYLE,
            ).ask()
            if lifecycle_env is None:
                do_promote = False
                lifecycle_env = ""

    # Step 6 — retention
    min_keep_raw = questionary.text(
        "Minimum Content View versions to keep:",
        default="1",
        validate=lambda v: v.isdigit() and int(v) >= 1 or "Enter a positive integer",
        style=STYLE,
    ).ask()
    min_keep = int(min_keep_raw) if min_keep_raw and min_keep_raw.isdigit() else 1

    return {
        "name": name,
        "org": org,
        "repos": all_repos,
        "content_view": cv,
        "lifecycle_env": lifecycle_env,
        "do_promote": bool(do_promote),
        "min_versions_to_keep": min_keep,
    }


# ---------------------------------------------------------------------------
# Config I/O
# ---------------------------------------------------------------------------
def load_existing(path: str) -> List[dict]:
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict) and isinstance(data.get("pipelines"), list):
            return data["pipelines"]
    except Exception as e:
        print(f"  ⚠  Could not parse existing config: {e}")
    return []


def write_config(pipelines: List[dict], path: str):
    header_comment = (
        f"# Foreman Pipeline Config\n"
        f"# Generated by foreman_config_gen.py on "
        f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"#\n"
        f"# Run all:  HAMMER_TOKEN=xxx foreman_pipeline.sh --config {path}\n"
        f"# Run one:  HAMMER_TOKEN=xxx foreman_pipeline.sh --config {path} --pipeline NAME\n"
    )
    body = yaml.dump(
        {"pipelines": pipelines},
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )

    # Write atomically
    dir_ = os.path.dirname(os.path.abspath(path))
    with tempfile.NamedTemporaryFile("w", dir=dir_, delete=False, suffix=".tmp") as f:
        f.write("---\n")
        f.write(header_comment)
        f.write("\n")
        f.write(body)
        tmp_path = f.name

    os.replace(tmp_path, path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Foreman Pipeline Config Generator")
    parser.add_argument("--output", "-o", default="./pipelines.yaml",
                        help="Output YAML file (default: ./pipelines.yaml)")
    args = parser.parse_args()
    output_file = args.output

    # Quick sanity checks before drawing any UI
    if not os.environ.get("HAMMER_TOKEN"):
        sys.exit("ERROR: HAMMER_TOKEN is not set")
    try:
        subprocess.run(["hammer", "--version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        sys.exit("ERROR: hammer CLI not found or not working")

    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║      Foreman Pipeline Config Generator           ║")
    print("╚══════════════════════════════════════════════════╝")
    print(f"  Output: {output_file}")

    pipelines: List[dict] = []

    # Offer to load existing
    if os.path.exists(output_file):
        print(f"\n  Found existing config: {output_file}")
        load = questionary.confirm(
            "Load existing pipelines and add to them?",
            default=True,
            style=STYLE,
        ).ask()
        if load:
            pipelines = load_existing(output_file)
            print(f"  Loaded {len(pipelines)} existing pipeline(s).")

    # Main loop
    while True:
        print()
        if pipelines:
            print(f"  Pipelines defined: {len(pipelines)}")
            for p in pipelines:
                print(f"    • {p['name']}")
        else:
            print("  No pipelines defined yet.")

        action = questionary.select(
            "What would you like to do?",
            choices=[
                questionary.Choice("Add a new pipeline",          value="add"),
                questionary.Choice("Review pipelines",            value="review"),
                questionary.Choice("Save config and exit",        value="save"),
                questionary.Choice("Quit without saving",         value="quit"),
            ],
            style=STYLE,
        ).ask()

        if action is None or action == "quit":
            confirm = questionary.confirm(
                "Quit without saving?", default=False, style=STYLE
            ).ask()
            if confirm:
                print("\nExited without saving.")
                sys.exit(0)

        elif action == "add":
            pipeline = build_pipeline()
            if pipeline:
                pipelines.append(pipeline)
                print(f"\n  ✔  Pipeline '{pipeline['name']}' added.")
            else:
                print("\n  Pipeline creation cancelled.")

        elif action == "review":
            if not pipelines:
                print("\n  No pipelines defined yet.")
            else:
                header("Pipelines")
                for p in pipelines:
                    print(f"\n  ● {p['name']}")
                    print(f"    Org:          {p['org']}")
                    repo_display = ', '.join(
                        (r['name'] if isinstance(r, dict) else r)
                        for r in p['repos']
                    ) if p['repos'] else '(none)'
                    print(f"    Repos:        {repo_display}")
                    print(f"    Content View: {p['content_view']}")
                    print(f"    Promote:      {p['do_promote']}"
                          + (f"  →  {p['lifecycle_env']}" if p['do_promote'] else ""))
                    print(f"    Min keep:     {p['min_versions_to_keep']}")

        elif action == "save":
            if not pipelines:
                confirm = questionary.confirm(
                    "No pipelines defined. Save empty config anyway?",
                    default=False,
                    style=STYLE,
                ).ask()
                if not confirm:
                    continue

            write_config(pipelines, output_file)
            print(f"\n  ✔  Config saved to: {output_file}")
            print()
            print(f"  Run all:  HAMMER_TOKEN=xxx foreman_pipeline.sh --config {output_file}")
            print(f"  Run one:  HAMMER_TOKEN=xxx foreman_pipeline.sh --config {output_file} --pipeline NAME")
            print()
            sys.exit(0)


if __name__ == "__main__":
    main()

