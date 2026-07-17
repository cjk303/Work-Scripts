#!/bin/bash
# vm_cred_tool.sh - Encrypt/decrypt VMware credentials using Fernet key

set -e

function usage() {
    echo "Usage:"
    echo "  $0 gen-key <key_file>                     # Generate a Fernet encryption key"
    echo "  $0 encrypt <key_file> <plain_file> <enc_file>   # Encrypt credentials"
    echo "  $0 decrypt <key_file> <enc_file> <dec_file>    # Decrypt credentials"
    exit 1
}

if [ $# -lt 2 ]; then
    usage
fi

ACTION=$1

case "$ACTION" in
    gen-key)
        KEY_FILE=$2
        python3 - <<EOF
from cryptography.fernet import Fernet
key = Fernet.generate_key()
with open("$KEY_FILE", "wb") as f:
    f.write(key)
print("Key generated and saved to $KEY_FILE")
EOF
        ;;

    encrypt)
        if [ $# -ne 4 ]; then usage; fi
        KEY_FILE=$2
        PLAIN_FILE=$3
        ENC_FILE=$4
        python3 - <<EOF
from cryptography.fernet import Fernet

key = open("$KEY_FILE", "rb").read()
fernet = Fernet(key)

with open("$PLAIN_FILE", "r") as f_in, open("$ENC_FILE", "wb") as f_out:
    for line in f_in:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        enc_line = fernet.encrypt(line.encode())
        f_out.write(enc_line + b"\\n")
print("Encrypted credentials saved to $ENC_FILE")
EOF
        ;;

    decrypt)
        if [ $# -ne 4 ]; then usage; fi
        KEY_FILE=$2
        ENC_FILE=$3
        DEC_FILE=$4
        python3 - <<EOF
from cryptography.fernet import Fernet

key = open("$KEY_FILE", "rb").read()
fernet = Fernet(key)

with open("$ENC_FILE", "rb") as f_in, open("$DEC_FILE", "w") as f_out:
    for enc_line in f_in:
        enc_line = enc_line.strip()
        if not enc_line:
            continue
        line = fernet.decrypt(enc_line).decode()
        f_out.write(line + "\\n")
print("Decrypted credentials saved to $DEC_FILE")
EOF
        ;;

    *)
        usage
        ;;
esac
