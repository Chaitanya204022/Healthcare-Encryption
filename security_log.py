"""
=============================================================================
security_log.py — Layer 6: Audit & Event Logging
=============================================================================
SECURITY CONCEPT:
  An audit log provides non-repudiation and forensic traceability.
  Every security-relevant action — logins, failures, encryptions,
  decryptions — is timestamped and written to security_log.txt.
  In a real system this log would be write-once and tamper-evident.
=============================================================================
"""

import os
from datetime import datetime

LOG_FILE = "security_log.txt"


def log_event(event_type: str, detail: str) -> None:
    """
    Append a timestamped security event to the audit log.

    Args:
        event_type: Short category label (e.g. 'LOGIN_SUCCESS', 'ENCRYPT').
        detail:     Human-readable description of the event.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}]  [{event_type:<20}]  {detail}\n"

    with open(LOG_FILE, "a") as f:
        f.write(entry)


def print_log() -> None:
    """Print the full audit log to the terminal."""
    print("\n" + "="*65)
    print("  Security Audit Log")
    print("="*65)
    if not os.path.exists(LOG_FILE):
        print("  No log entries found.")
        return
    with open(LOG_FILE, "r") as f:
        contents = f.read()
    print(contents if contents.strip() else "  Log is empty.")
    print("="*65 + "\n")
