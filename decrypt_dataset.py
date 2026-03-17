"""
=============================================================================
decrypt_dataset.py — Layer 5: Authenticated Decryption
=============================================================================
SECURITY CONCEPT:
  Decryption reverses the encryption pipeline but ONLY after:
    1. Successful authentication (password verified via SHA-256).
    2. PBKDF2 key regeneration using the SAME password + stored salt.
    3. AES-GCM authentication tag verification — if the ciphertext
       or tag has been modified in any way, decryption raises an
       error and NO plaintext is returned. This prevents an attacker
       from feeding tampered ciphertext to the system.

WHY GCM'S AUTH TAG MATTERS:
  Without authentication, an attacker could flip bits in the ciphertext
  (bit-flipping attack) and silently corrupt the decrypted output.
  GCM's 128-bit MAC makes such attacks detectable with overwhelming
  probability (2^-128 chance of an undetected forgery).

FILE LAYOUT READ FROM encrypted_dataset.bin:
  Bytes  0–15  → nonce     (16 bytes)
  Bytes 16–31  → auth_tag  (16 bytes)
  Bytes 32+    → ciphertext (remainder)
=============================================================================

USAGE:
    python decrypt_dataset.py
"""

import os
import sys
import io
import pandas as pd
from Crypto.Cipher import AES
InvalidTag = ValueError  # raised on auth failure

from login_security import authenticate, load_or_create_salt, derive_key
from security_log    import log_event, print_log

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ENCRYPTED_FILE = "encrypted_dataset.bin"


# ---------------------------------------------------------------------------
# Decryption
# ---------------------------------------------------------------------------

def load_encrypted_file(path: str) -> tuple[bytes, bytes, bytes]:
    """
    Read encrypted_dataset.bin and split into its three components.
    Layout: [ 16-byte nonce ][ 16-byte auth_tag ][ ciphertext... ]
    """
    if not os.path.exists(path):
        print(f"❌  Encrypted file not found: {path}")
        print("    Run encrypt_dataset.py first.")
        log_event("ERROR", f"Encrypted file missing: {path}")
        sys.exit(1)

    with open(path, "rb") as f:
        raw = f.read()

    nonce      = raw[:16]
    auth_tag   = raw[16:32]
    ciphertext = raw[32:]

    size_kb = len(raw) / 1024
    print(f"📂  Encrypted file loaded: {path}  ({size_kb:.1f} KB)")
    print(f"    Nonce    : {nonce.hex()}")
    print(f"    Auth Tag : {auth_tag.hex()}")
    return nonce, auth_tag, ciphertext


def decrypt_data(ciphertext: bytes, key: bytes, nonce: bytes, auth_tag: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-256-GCM and verify the authentication tag.

    Raises:
        InvalidTag — if the ciphertext or tag has been tampered with.
                     This is caught below and results in a hard abort.
    Returns:
        Verified plaintext bytes.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # decrypt_and_verify raises InvalidTag on any integrity failure
    plaintext = cipher.decrypt_and_verify(ciphertext, auth_tag)
    return plaintext


def display_dataset(plaintext: bytes) -> None:
    """Parse decrypted CSV bytes back into a DataFrame and display it."""
    df = pd.read_csv(io.StringIO(plaintext.decode("utf-8")))
    print("\n" + "="*65)
    print("  Decrypted Healthcare Dataset")
    print("="*65)
    print(df.to_string(index=False))
    print("="*65)
    print(f"\n  Rows: {len(df)}   Columns: {len(df.columns)}")
    return df


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def main() -> None:
    print("\n" + "="*55)
    print("   Healthcare Data Decryption Pipeline")
    print("="*55)

    # --- Layer 1 & 2: Authenticate + regenerate key ---
    password = authenticate()
    salt     = load_or_create_salt()   # loads existing salt.bin
    key      = derive_key(password, salt)

    # --- Layer 5: Load and decrypt ---
    print("\n📋  Starting decryption pipeline...")
    nonce, auth_tag, ciphertext = load_encrypted_file(ENCRYPTED_FILE)

    print("🔓  Verifying authentication tag and decrypting...")
    try:
        plaintext = decrypt_data(ciphertext, key, nonce, auth_tag)
    except ValueError:
        # Authentication tag mismatch — ciphertext has been tampered with
        # or the wrong password/salt was used.
        msg = "Authentication tag verification FAILED. Data may be tampered or key is wrong."
        print(f"\n🚨  INTEGRITY ERROR: {msg}")
        log_event("INTEGRITY_FAILURE", msg)
        sys.exit(1)

    # --- Display result ---
    df = display_dataset(plaintext)

    # --- Layer 6: Audit ---
    log_event("DECRYPT", f"{ENCRYPTED_FILE} decrypted successfully. "
                          f"Rows: {len(df)}, Columns: {len(df.columns)}.")

    print("\n✅  Decryption and integrity verification successful.\n")

    # Optionally print the audit log at the end
    show_log = input("📋  Show full security audit log? (y/n): ").strip().lower()
    if show_log == "y":
        print_log()


if __name__ == "__main__":
    main()
