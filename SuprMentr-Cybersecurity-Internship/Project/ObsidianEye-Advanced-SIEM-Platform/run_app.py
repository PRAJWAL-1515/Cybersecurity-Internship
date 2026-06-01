"""
App Loader Tool
-------------------------------------
Decrypts the encrypted bundle back to usable files.
Run: python decrypt_project.py
"""

import os
import sys
import getpass
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

ENCRYPTED_BUNDLE = "config.dat"
OUTPUT_DIR       = "app_data"

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return kdf.derive(password.encode())

def decrypt_project():
    print("\n🔓 App Loader")
    print("=" * 40)

    bundle_path = os.path.join(os.path.dirname(__file__), ENCRYPTED_BUNDLE)
    if not os.path.exists(bundle_path):
        print(f"❌ Bundle not found: {ENCRYPTED_BUNDLE}")
        sys.exit(1)

    with open(bundle_path, "r") as f:
        bundle = json.load(f)

    password = getpass.getpass("Enter decryption password: ")
    salt     = base64.b64decode(bundle["salt"])
    key      = derive_key(password, salt)
    aesgcm   = AESGCM(key)

    out_dir = os.path.join(os.path.dirname(__file__), OUTPUT_DIR)
    os.makedirs(out_dir, exist_ok=True)

    try:
        for rel, payload in bundle["files"].items():
            nonce = base64.b64decode(payload["nonce"])
            ct    = base64.b64decode(payload["data"])
            data  = aesgcm.decrypt(nonce, ct, None)

            out_path = os.path.join(out_dir, rel)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "wb") as f:
                f.write(data)
            print(f"  ✅ Decrypted: {rel}")
    except InvalidTag:
        print("\n❌ Wrong password or corrupted file. Decryption failed.")
        sys.exit(1)

    print(f"\n✅ Project restored to: {OUTPUT_DIR}/")

if __name__ == "__main__":
    decrypt_project()
