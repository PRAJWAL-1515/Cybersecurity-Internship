"""
Project Setup Tool Tool
------------------------------------
Encrypts every file in the project folder.
Run: python encrypt_project.py
"""

import os
import sys
import getpass
import zipfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import json

SALT_FILE = "obsidianeye.salt"
ENCRYPTED_BUNDLE = "config.dat"

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return kdf.derive(password.encode())

def encrypt_project(project_dir: str):
    print("\n🔐 Project Setup Tool")
    print("=" * 40)

    password = getpass.getpass("Enter encryption password: ")
    confirm  = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("❌ Passwords do not match. Aborting.")
        sys.exit(1)

    salt = os.urandom(32)
    key  = derive_key(password, salt)
    aesgcm = AESGCM(key)

    encrypted_files = {}

    for root, _, files in os.walk(project_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel   = os.path.relpath(fpath, project_dir)
            with open(fpath, "rb") as f:
                data = f.read()
            nonce = os.urandom(12)
            ct    = aesgcm.encrypt(nonce, data, None)
            encrypted_files[rel] = {
                "nonce": base64.b64encode(nonce).decode(),
                "data":  base64.b64encode(ct).decode(),
            }
            print(f"  ✅ Encrypted: {rel}")

    bundle = {
        "salt":  base64.b64encode(salt).decode(),
        "files": encrypted_files,
    }
    bundle_path = os.path.join(os.path.dirname(project_dir), ENCRYPTED_BUNDLE)
    with open(bundle_path, "w") as f:
        json.dump(bundle, f)

    print(f"\n✅ Done! Encrypted bundle saved to: {ENCRYPTED_BUNDLE}")
    print("⚠️  Keep your password safe — without it, files CANNOT be recovered.")
    return bundle_path

if __name__ == "__main__":
    project_dir = os.path.join(os.path.dirname(__file__), "app_source", "siem_v4_fixed")
    if not os.path.exists(project_dir):
        print("❌ Project folder not found.")
        sys.exit(1)
    encrypt_project(project_dir)
