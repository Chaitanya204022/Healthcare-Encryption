"""
=============================================================================
login_security.py — Layer 1 & 2: Access Control + Key Derivation
=============================================================================
SECURITY LAYERS IMPLEMENTED:
  Layer 1 — Authentication: SHA-256 hashed passwords, 3-attempt lockout,
             secure input via getpass (password never echoed to terminal).
  Layer 2 — Key Derivation: PBKDF2-HMAC-SHA256 converts the user password
             into a 256-bit AES key. A random salt prevents rainbow-table
             attacks; 200,000 iterations slow down brute-force attempts.

WHY PBKDF2 + SALT?
  A raw password is short and guessable. PBKDF2 stretches it into a strong
  cryptographic key. The random salt ensures that two users with the same
  password produce completely different keys — defeating pre-computed
  dictionary attacks.
=============================================================================
"""

import hashlib
import os
import getpass
from security_log import log_event

# ---------------------------------------------------------------------------
# Registered users — passwords stored as SHA-256 hashes, NEVER plaintext.
# In production this would live in a secure database.
# ---------------------------------------------------------------------------
USER_DB = {
    "admin":    hashlib.sha256(b"Admin@1234").hexdigest(),
    "doctor":   hashlib.sha256(b"Doctor@5678").hexdigest(),
    "nurse":    hashlib.sha256(b"Nurse@9012").hexdigest(),
}

MAX_ATTEMPTS   = 3       # lockout threshold
PBKDF2_ITERS   = 200_000 # iteration count — higher = slower brute force
KEY_LENGTH     = 32      # 32 bytes = 256 bits (AES-256)
SALT_FILE      = "salt.bin"


# ---------------------------------------------------------------------------
# Layer 1 — Authentication
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Return the SHA-256 hex digest of a plaintext password."""
    return hashlib.sha256(password.encode()).hexdigest()


def authenticate() -> str:
    """
    Prompt for credentials up to MAX_ATTEMPTS times.
    Returns the plaintext password on success (needed for key derivation).
    Exits the process after MAX_ATTEMPTS failures.
    """
    print("\n" + "="*55)
    print("   Healthcare Data Protection System — Login")
    print("="*55)

    for attempt in range(1, MAX_ATTEMPTS + 1):
        username = input(f"\n[{attempt}/{MAX_ATTEMPTS}] Username: ").strip()
        # getpass hides typing — password never appears on screen
        password = getpass.getpass("           Password: ")

        if username in USER_DB and USER_DB[username] == hash_password(password):
            log_event("LOGIN_SUCCESS", f"User '{username}' authenticated successfully.")
            print(f"\n✅  Access granted. Welcome, {username}.\n")
            return password   # plaintext needed only for PBKDF2 — never stored
        else:
            remaining = MAX_ATTEMPTS - attempt
            log_event("LOGIN_FAILURE", f"Failed attempt {attempt} for username '{username}'.")
            if remaining > 0:
                print(f"❌  Invalid credentials. {remaining} attempt(s) remaining.")
            else:
                log_event("LOCKOUT", "Maximum login attempts reached. System locked.")
                print("\n🔒  Maximum attempts exceeded. Access denied. Exiting.\n")
                raise SystemExit(1)


# ---------------------------------------------------------------------------
# Layer 2 — PBKDF2 Key Derivation
# ---------------------------------------------------------------------------

def load_or_create_salt() -> bytes:
    """
    Load an existing salt from disk, or generate and save a new one.
    The salt is random and unique per installation — stored in salt.bin.
    It is NOT secret but must be preserved to regenerate the same key.
    """
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
        print(f"🔑  Salt loaded from {SALT_FILE}.")
    else:
        salt = os.urandom(32)   # 256-bit cryptographically random salt
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        print(f"🔑  New salt generated and saved to {SALT_FILE}.")
        log_event("SALT_CREATED", "New random salt generated and stored.")
    return salt


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from the user's password using PBKDF2-HMAC-SHA256.

    WHY THIS MATTERS:
      - Raw passwords are weak; PBKDF2 makes them cryptographically strong.
      - 200,000 iterations means an attacker must do 200k SHA-256 operations
        per guess — making brute-force prohibitively slow.
      - The salt makes every derived key unique even for identical passwords.

    Returns: 32-byte key ready for AES-256.
    """
    key = hashlib.pbkdf2_hmac(
        hash_name   = "sha256",
        password    = password.encode("utf-8"),
        salt        = salt,
        iterations  = PBKDF2_ITERS,
        dklen       = KEY_LENGTH,
    )
    print(f"🔐  AES-256 key derived via PBKDF2 ({PBKDF2_ITERS:,} iterations).")
    return key
