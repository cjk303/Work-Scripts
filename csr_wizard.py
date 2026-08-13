#!/usr/bin/env python3
"""
Interactive CSR generator for EPIQ4K Web Server template
"""

import os
import subprocess
import tempfile
import textwrap
from pathlib import Path
from getpass import getpass


def ask(prompt, default=None, required=False, secret=False):
    while True:
        p = f"{prompt}"
        if default:
            p += f" [{default}]"
        p += ": "
        val = getpass(p) if secret else input(p).strip()
        if not val and default is not None:
            val = default
        if required and not val:
            print("  -> This field is required.")
            continue
        return val


def ask_multiple(label):
    print(f"{label} (enter one per line; blank line to finish)")
    items = []
    while True:
        s = input("> ").strip()
        if not s:
            break
        items.append(s)
    return items


def run(cmd, **kwargs):
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,   # ✅ FIXED HERE
        **kwargs
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command failed:\n{' '.join(cmd)}\n"
            f"STDOUT:\n{proc.stdout}\n\nSTDERR:\n{proc.stderr}"
        )
    return proc.stdout


def secure_write(path: Path, data: str, mode=0o600):
    path.write_text(data)
    os.chmod(path, mode)


def main():
    print("=== CSR Wizard for EPIQ4K Web Server ===\n")

    country = ask("Country (C)", default="US", required=True)
    state = ask("State or Province (ST)", default="NY", required=True)
    locality = ask("Locality/City (L)", default="NY", required=True)
    org = ask("Organization (O)", default="Epiq", required=True)
    cn = ask("Common Name (CN) - primary FQDN",
             default="p054lnxfore01.epiqcorp.com",
             required=True)

    print("\nSubject Alternative Names (SAN - DNS):")
    sans = ask_multiple("Add DNS names")
    if cn and cn not in sans:
        sans.insert(0, cn)

    key_bits = ask("Key size (rsa)", default="4096", required=True)
    digest = ask("Digest (md)", default="sha256", required=True)

    out_dir = ask("Output directory", default=str(Path.cwd()))
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    default_base = cn.replace(".", "_")
    base_name = ask("Base file name", default=default_base)
    base_name = base_name.replace("/", "_").replace(" ", "_")

    key_path = out_path / f"{base_name}.key.pem"
    csr_path = out_path / f"{base_name}.csr.pem"

    print_key_once = ask(
        "Display private key once on screen? (yes/no)",
        default="no"
    ).lower().startswith("y")

    alt_names_lines = [f"DNS.{i+1} = {dns}" for i, dns in enumerate(sans)]
    alt_names_block = "\n".join(alt_names_lines) if alt_names_lines else f"DNS.1 = {cn}"

    openssl_cfg = textwrap.dedent(f"""
        [ req ]
        default_bits       = {key_bits}
        default_md         = {digest}
        distinguished_name = req_distinguished_name
        req_extensions     = req_ext
        prompt             = no

        [ req_distinguished_name ]
        C  = {country}
        ST = {state}
        L  = {locality}
        O  = {org}
        CN = {cn}

        [ req_ext ]
        subjectAltName   = @alt_names
        keyUsage         = critical, digitalSignature, keyEncipherment
        extendedKeyUsage = serverAuth

        [ alt_names ]
        {alt_names_block}
    """).strip()

    with tempfile.NamedTemporaryFile("w", delete=False) as tmp_cfg:
        cfg_path = Path(tmp_cfg.name)
        tmp_cfg.write(openssl_cfg)

    try:
        print("\n-> Generating RSA key and CSR with OpenSSL...")

        cmd = [
            "openssl", "req",
            "-new",
            "-newkey", f"rsa:{key_bits}",
            "-nodes",
            "-keyout", str(key_path),
            "-out", str(csr_path),
            "-config", str(cfg_path),
            f"-{digest}",
        ]

        run(cmd)

        os.chmod(key_path, 0o600)
        os.chmod(csr_path, 0o644)

        print(f"\n✅ CSR created: {csr_path}")
        print(f"🔐 Private key saved (mode 600): {key_path}")

        print("\n--- BEGIN CSR ---")
        print(csr_path.read_text())
        print("--- END CSR ---")

    finally:
        try:
            cfg_path.unlink(missing_ok=True)
        except Exception:
            pass


if __name__ == "__main__":
    main()
