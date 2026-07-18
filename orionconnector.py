#!/usr/bin/env python3
import argparse
import base64
import requests
import urllib3
from datetime import datetime, timedelta, timezone
import logging
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Logging setup ---
#logging.basicConfig(filename='orion_actions.log', level=logging.INFO,
#                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Credentials & API base ---
ENCODED_PASSWORD = "ZFhLbT9ZQCshbFV3WEpcYXpSd0k="
USERNAME = "svc_server_ops"
API_BASE = "https://orion.epiqcorp.com:17774/SolarWinds/InformationService/v3/Json"
QUERY_URL = f"{API_BASE}/Query"

HEADERS = {"Content-Type": "application/json"}
DEFAULT_DOMAIN = "epiqcorp.com"

# -------- Utilities --------
def decode_password(encoded: str) -> str:
    return base64.b64decode(encoded).decode("ascii")

def normalize(hostname: str, domain: str = DEFAULT_DOMAIN) -> tuple[str, str]:
    short = hostname.split(".")[0].strip()
    fqdn = f"{short}.{domain}"
    return short, fqdn

def parse_duration(value: str) -> int:
    """
    Accepts '1', '1h', '1H' and returns integer hours.
    """
    value = value.strip()
    if value.lower().endswith('h'):
        value = value[:-1]
    return int(value)

# -------- Orion SWIS helpers --------
def get_node_info(session: requests.Session, hostname: str, domain: str = DEFAULT_DOMAIN) -> dict:
    short, fqdn = normalize(hostname, domain)
    swql = f"""
        SELECT NodeID, NodeName, Uri
        FROM Orion.Nodes
        WHERE NodeName = '{short}' OR NodeName = '{fqdn}' OR IPAddress = '{hostname}'
    """
    resp = session.post(QUERY_URL, json={"query": swql}, headers=HEADERS)
    if resp.status_code != 200:
        raise RuntimeError(f"Query failed: {resp.status_code} {resp.text}")
    data = resp.json()
    results = data.get("results", [])
    if not results:
        raise LookupError(f"Hostname/IP '{hostname}' not found in Orion.")
    return results[0]

def log_and_print(message, success=True):
    color = Fore.GREEN if success else Fore.RED
    print(color + message + Style.RESET_ALL)
    (logging.info if success else logging.error)(message)

# -------- Actions --------
def unmanage_node(session, node_id, hostname, hours=None):
    net_object_id = f"N:{node_id}"
    now_utc = datetime.now(timezone.utc)
    start_utc = now_utc.isoformat()
    end_utc = (now_utc + timedelta(hours=hours)).isoformat() if hours is not None else \
              (now_utc + timedelta(days=99*365)).isoformat()
    url = f"{API_BASE}/Invoke/Orion.Nodes/Unmanage"
    payload = [net_object_id, start_utc, end_utc, False]
    resp = session.post(url, json=payload, headers=HEADERS)
    if resp.status_code == 200:
        duration_text = f"{hours} hours" if hours is not None else "indefinitely"
        log_and_print(f"Node '{hostname}' unmanaged for {duration_text} (until {end_utc} UTC).")
    else:
        log_and_print(f"Failed to unmanage node: {resp.status_code} {resp.text}", success=False)

def manage_node(session, node_id, hostname):
    net_object_id = f"N:{node_id}"
    url = f"{API_BASE}/Invoke/Orion.Nodes/Remanage"
    payload = [net_object_id]
    resp = session.post(url, json=payload, headers=HEADERS)
    if resp.status_code == 200:
        log_and_print(f"Node '{hostname}' re-managed successfully.")
    else:
        log_and_print(f"Failed to re-manage node: {resp.status_code} {resp.text}", success=False)

def mute_node(session, node_uri, hours):
    now_utc = datetime.now(timezone.utc)
    start_utc = now_utc.isoformat()
    end_utc = (now_utc + timedelta(hours=hours)).isoformat()
    url = f"{API_BASE}/Invoke/Orion.AlertSuppression/SuppressAlerts"
    payload = [[node_uri if node_uri.startswith("swis://") else f"swis://{node_uri}"], start_utc, end_utc]
    resp = session.post(url, json=payload, headers=HEADERS)
    if resp.status_code == 200:
        log_and_print(f"Node muted for {hours} hours (until {end_utc} UTC).")
    else:
        log_and_print(f"Failed to mute node: {resp.status_code} {resp.text}", success=False)

def unmute_node(session, node_uri, hostname):
    url = f"{API_BASE}/Invoke/Orion.AlertSuppression/ResumeAlerts"
    payload = [[node_uri if node_uri.startswith("swis://") else f"swis://{node_uri}"]]
    resp = session.post(url, json=payload, headers=HEADERS)
    if resp.status_code == 200:
        log_and_print(f"Alerts resumed for node '{hostname}'.")
    else:
        log_and_print(f"Failed to unmute node: {resp.status_code} {resp.text}", success=False)

def set_custom_property(session, node_uri, prop_name, prop_value):
    """
    Update an existing custom property on the node.
    Uses the node's Uri returned by SWIS (prepends swis:// if missing).
    """
    log_and_print(f"Ensure custom property '{prop_name}' exists in Orion before running this command.", success=True)
    url = f"{API_BASE}/Update"
    uri = node_uri if node_uri.startswith("swis://") else f"swis://{node_uri}"
    payload = {
        "Uri": uri,
        "properties": {
            "CustomProperties": {
                prop_name: prop_value
            }
        }
    }
    resp = session.post(url, json=payload, headers=HEADERS)
    if resp.status_code == 200:
        log_and_print(f"Custom property '{prop_name}' set to '{prop_value}'.")
    else:
        # Try to surface SWIS error JSON for faster troubleshooting
        try:
            err = resp.json()
            log_and_print(f"Failed to set property: {resp.status_code} {err}", success=False)
        except Exception:
            log_and_print(f"Failed to set property: {resp.status_code} {resp.text}", success=False)

# -------- CLI --------
def build_parser():
    examples = """
Examples:
  # Unmanage node indefinitely
  python orionconnector.py --node d054lnxutil03 --unmanage

  # Unmanage node for 2 hours
  python orionconnector.py --node d054lnxutil03 --unmanage --time 2

  # Re-manage node
  python orionconnector.py --node d054lnxutil03 --manage

  # Mute alerts for 1 hour (supports 1 or 1h)
  python orionconnector.py --node d054lnxutil03 --mute --time 1h

  # Unmute alerts
  python orionconnector.py --node d054lnxutil03 --unmute

  # Set custom property (property must exist in Orion)
  python orionconnector.py --node d054lnxutil03 --set-property PrimaryContact --property-value "serverops@epiqcorp.com"
"""
    p = argparse.ArgumentParser(
        description="SolarWinds Orion node actions and custom property updates via SWIS",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=examples,
    )
    p.add_argument("--node", help="Hostname, FQDN, or IP address")
    p.add_argument("--domain", default=DEFAULT_DOMAIN, help="Domain for FQDN normalization")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--unmanage", action="store_true", help="Unmanage node (indefinitely or for --time hours)")
    g.add_argument("--manage", action="store_true", help="Re-manage node immediately")
    g.add_argument("--mute", action="store_true", help="Mute alerts for specified hours")
    g.add_argument("--unmute", action="store_true", help="Resume alerts immediately")
    p.add_argument("--time", type=parse_duration, help="Duration in hours for unmanage or mute (e.g., 1 or 1h)")
    p.add_argument("--set-property", help="Custom property name to set")
    p.add_argument("--property-value", help="Value for the custom property")
    return p

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.node:
        log_and_print("Error: --node is required", success=False)
        return

    session = requests.Session()
    session.auth = (USERNAME, decode_password(ENCODED_PASSWORD))
    session.verify = False

    try:
        node = get_node_info(session, args.node, args.domain)
        log_and_print(f"Target node: {node['NodeName']} (NodeID={node['NodeID']})")

        if args.unmanage:
            unmanage_node(session, node["NodeID"], node["NodeName"], args.time)
        elif args.manage:
            manage_node(session, node["NodeID"], node["NodeName"])
        elif args.mute:
            if args.time is None:
                log_and_print("Error: --time is required for mute (e.g., --time 1 or --time 1h)", success=False)
                return
            mute_node(session, node["Uri"], args.time)
        elif args.unmute:
            unmute_node(session, node["Uri"], node["NodeName"])
        elif args.set_property and args.property_value:
            set_custom_property(session, node["Uri"], args.set_property, args.property_value)
        else:
            log_and_print("No action specified. Use --unmanage, --manage, --mute, --unmute, or --set-property.", success=False)
    except Exception as e:
        log_and_print(f"Error: {e}", success=False)

if __name__ == "__main__":
    main()

