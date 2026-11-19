# Secure Password Manager

A command-line password manager in Python that stores credentials in an encrypted vault protected by a master password.

## Features
- Master-password protected vault (3 attempts limit)
- Strong encryption: **Scrypt** key derivation + **Fernet (AES-128-CBC + HMAC-SHA256)**
- Add / view / list / search / update / delete credentials
- Cryptographically secure password generator (`secrets` module)
- Password strength checker with suggestions
- Change master password (re-encrypts with a fresh salt)
- Atomic file writes and `chmod 600` on the vault file

## Tech Stack
Python 3.8+, `cryptography` library

## Installation & Run
```bash
pip install -r requirements.txt
python password_manager.py
```
First run asks you to create a master password. Use `VAULT_FILE=path python password_manager.py` to change vault location.

## How It Works
1. **First run:** random 16-byte salt is generated; the master password + salt go through Scrypt (n=2^15, r=8, p=1) to derive a 256-bit key.
2. **Saving:** all entries are serialized to JSON, encrypted with Fernet and written to `vault.dat` along with the salt. The master password is **never stored**.
3. **Unlocking:** the key is re-derived; Fernet's HMAC check fails on a wrong password, so no plain-text comparison is needed.

## Security Design
| Threat | Defense |
|---|---|
| Vault file stolen | AES encryption, nothing readable without master password |
| Brute-force / dictionary attack | Scrypt is memory-hard and slow; unique random salt |
| File tampering | Fernet authenticated encryption detects modification |
| Weak passwords | Strength checker; master password must score >= 3/5 |
| Corrupted file on crash | Write to temp file, then atomic replace |
| Predictable generated passwords | `secrets` (OS CSPRNG), not `random` |

## Project Structure
```
password_manager/
├── password_manager.py   # complete application
├── requirements.txt
└── README.md
```

## Limitations & Future Scope
- No clipboard auto-clear or GUI yet (can add Tkinter / web UI)
- No cloud sync or 2FA
- Cloud backup, browser extension, breach check (HaveIBeenPwned API)

## Conclusion
The project demonstrates applied cryptography, secure key derivation and safe credential handling in a simple, usable tool.
