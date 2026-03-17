"""
=============================================================================
encrypt_dataset.py — Layer 3 & 4: AES-256-GCM Encryption + Secure Storage
=============================================================================
SECURITY LAYERS IMPLEMENTED:
  Layer 3 — Encryption: AES-256 in GCM mode.
    • AES-256: Industry-standard symmetric cipher; 256-bit key gives
      2^256 possible keys — computationally infeasible to brute-force.
    • GCM mode: Provides both CONFIDENTIALITY (encryption) and
      INTEGRITY (authentication tag). If even one byte of ciphertext
      is modified, decryption will fail — detecting tampering.

  Layer 4 — Secure Storage:
    • Only salt.bin and encrypted_dataset.bin are written to disk.
    • The plaintext password and AES key are NEVER persisted.
    • Ciphertext is opaque binary data — meaningless without the key.

WHAT IS CIPHERTEXT?
  Ciphertext is the result of applying AES to plaintext bytes using a
  secret key. It is statistically indistinguishable from random noise.
  Without the exact key, recovering plaintext is computationally impossible.

FILE LAYOUT OF encrypted_dataset.bin:
  [ 16-byte nonce ][ 16-byte auth tag ][ variable-length ciphertext ]
=============================================================================

USAGE:
    python encrypt_dataset.py

PREREQUISITES:
    pip install pycryptodome pandas openpyxl
"""

import os
import sys
import pandas as pd
from Crypto.Cipher import AES

from login_security import authenticate, load_or_create_salt, derive_key
from security_log    import log_event

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INPUT_FILE  = "dataset.xlsx"
OUTPUT_FILE = "encrypted_dataset.bin"


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def load_dataset(filepath: str) -> bytes:
    """
    Read dataset.xlsx and serialise it to CSV bytes for encryption.
    CSV is used as the serialisation format — simple and portable.
    """
    if not os.path.exists(filepath):
        print(f"❌  Dataset file not found: {filepath}")
        log_event("ERROR", f"Input file missing: {filepath}")
        sys.exit(1)

    df = pd.read_excel(filepath)
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    print(f"📂  Dataset loaded: {filepath}  ({len(df)} rows, {len(df.columns)} columns)")
    log_event("DATA_LOADED", f"Loaded {filepath} — {len(df)} rows.")
    return csv_bytes


def encrypt_data(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext using AES-256-GCM.

    AES-GCM produces three outputs:
      nonce      — 16-byte random number used once; must be unique per encryption.
                   Safe to store alongside ciphertext (not secret).
      auth_tag   — 16-byte MAC that guarantees integrity; decryption fails if
                   ciphertext or tag has been altered.
      ciphertext — encrypted payload; unintelligible without the key.

    Returns: (nonce, auth_tag, ciphertext)
    """
    cipher     = AES.new(key, AES.MODE_GCM)          # fresh nonce generated internally
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, auth_tag, ciphertext


def save_encrypted_file(nonce: bytes, auth_tag: bytes, ciphertext: bytes, path: str) -> None:
    """
    Write [ nonce | auth_tag | ciphertext ] to a binary file.
    Layout is fixed-width for easy parsing during decryption.
    """
    with open(path, "wb") as f:
        f.write(nonce)        # 16 bytes
        f.write(auth_tag)     # 16 bytes
        f.write(ciphertext)   # variable
    size_kb = os.path.getsize(path) / 1024
    print(f"💾  Encrypted file saved: {path}  ({size_kb:.1f} KB)")


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def main() -> None:
    print("\n" + "="*55)
    print("   Healthcare Data Encryption Pipeline")
    print("="*55)

    # --- Layer 1 & 2: Authenticate + derive key ---
    password = authenticate()
    salt     = load_or_create_salt()
    key      = derive_key(password, salt)

    # --- Layer 3: Encrypt ---
    print("\n📋  Starting encryption pipeline...")
    plaintext              = load_dataset(INPUT_FILE)
    nonce, auth_tag, ciphertext = encrypt_data(plaintext, key)

    # --- Layer 4: Save ---
    save_encrypted_file(nonce, auth_tag, ciphertext, OUTPUT_FILE)

    # --- Layer 6: Audit ---
    log_event("ENCRYPT", f"dataset.xlsx encrypted → {OUTPUT_FILE}. "
                          f"Plaintext: {len(plaintext)} B, Ciphertext: {len(ciphertext)} B.")

    print("\n✅  Encryption complete!")
    print(f"    Plaintext size  : {len(plaintext):,} bytes")
    print(f"    Ciphertext size : {len(ciphertext):,} bytes")
    print(f"    Nonce           : {nonce.hex()}")
    print(f"    Auth Tag        : {auth_tag.hex()}")
    print(f"\n🔒  Original data is now protected. Only the correct password")
    print(f"    and salt.bin can recover it.\n")


if __name__ == "__main__":
    main()
