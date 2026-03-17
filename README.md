# 🏥 Healthcare Data Protection System

A modular Python project demonstrating **AES-256-GCM encryption**, **PBKDF2 key derivation**, and **secure authentication** applied to a healthcare dataset.

---

## Architecture Overview

```
dataset.xlsx
    │
    ▼
┌─────────────────────────────────────────────────┐
│  Layer 1 — Authentication (SHA-256 + getpass)   │
│  Layer 2 — Key Derivation (PBKDF2 + salt.bin)   │
│  Layer 3 — AES-256-GCM Encryption               │
│  Layer 4 — Secure Storage (encrypted_dataset.bin)│
│  Layer 6 — Audit Logging  (security_log.txt)    │
└─────────────────────────────────────────────────┘
    │
    ▼
encrypted_dataset.bin

─── Decryption ──────────────────────────────────────

encrypted_dataset.bin
    │
    ▼
┌─────────────────────────────────────────────────┐
│  Layer 1 — Re-authentication                    │
│  Layer 2 — Key Regeneration (PBKDF2 + salt.bin) │
│  Layer 5 — AES-GCM Decrypt + Tag Verification   │
└─────────────────────────────────────────────────┘
    │
    ▼
Plaintext dataset printed to terminal
```

---

## Project Structure

```
healthcare_security/
├── encrypt_dataset.py   # Encryption pipeline
├── decrypt_dataset.py   # Decryption pipeline
├── login_security.py    # Auth + PBKDF2 key derivation
├── security_log.py      # Audit logging
├── dataset.xlsx         # ← place your dataset here
├── salt.bin             # generated on first run
├── encrypted_dataset.bin# generated after encryption
└── security_log.txt     # generated automatically
```

---

## Setup

```bash
# 1. Clone or copy project files into a folder
cd healthcare_security

# 2. Install dependencies
pip install pycryptodome pandas openpyxl

# 3. Place your dataset.xlsx in the same folder
```

---

## Running

### Step 1 — Encrypt
```bash
python encrypt_dataset.py
```
Login credentials (pre-configured):
| Username | Password     |
|----------|-------------|
| admin    | Admin@1234  |
| doctor   | Doctor@5678 |
| nurse    | Nurse@9012  |

### Step 2 — Decrypt
```bash
python decrypt_dataset.py
```

---

## Security Properties

| Property        | Implementation                          |
|----------------|-----------------------------------------|
| Confidentiality | AES-256-GCM encryption                 |
| Integrity       | GCM authentication tag (128-bit MAC)   |
| Authentication  | SHA-256 hashed passwords               |
| Key Strength    | PBKDF2-HMAC-SHA256, 200,000 iterations |
| Brute-force     | 3-attempt lockout                      |
| Non-repudiation | Timestamped audit log                  |

---

## Security Notes

- Passwords are **never stored in plaintext** — only SHA-256 hashes
- The AES key is **never written to disk** — derived fresh each session
- `salt.bin` must be kept alongside `encrypted_dataset.bin` to decrypt
- Losing `salt.bin` makes the encrypted data **unrecoverable**
