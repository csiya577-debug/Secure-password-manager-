#!/usr/bin/env python3
"""
Secure Password Manager
-----------------------
- Master password se vault lock hota hai
- Key derivation : Scrypt (salt ke saath, brute-force resistant)
- Encryption     : Fernet (AES-128-CBC + HMAC-SHA256, authenticated)
- Passwords generate karna, strength check, search, update, delete
"""

import base64
import getpass
import json
import os
import secrets
import string
import sys
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VAULT_FILE = os.environ.get("VAULT_FILE", "vault.dat")
MAX_ATTEMPTS = 3


# --------------------------------------------------------------------------
# Crypto helpers
# --------------------------------------------------------------------------
def derive_key(master_password: str, salt: bytes) -> bytes:
    """Master password + salt se 32-byte key banata hai (Scrypt)."""
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


def encrypt_vault(entries: dict, key: bytes) -> str:
    payload = json.dumps(entries).encode("utf-8")
    return Fernet(key).encrypt(payload).decode("utf-8")


def decrypt_vault(token: str, key: bytes) -> dict:
    payload = Fernet(key).decrypt(token.encode("utf-8"))
    return json.loads(payload.decode("utf-8"))


# --------------------------------------------------------------------------
# Vault storage
# --------------------------------------------------------------------------
class Vault:
    def __init__(self, path: str = VAULT_FILE):
        self.path = path
        self.salt = b""
        self.key = b""
        self.entries = {}

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def create(self, master_password: str):
        self.salt = os.urandom(16)
        self.key = derive_key(master_password, self.salt)
        self.entries = {}
        self.save()

    def unlock(self, master_password: str) -> bool:
        with open(self.path, "r", encoding="utf-8") as f:
            blob = json.load(f)
        self.salt = base64.b64decode(blob["salt"])
        key = derive_key(master_password, self.salt)
        try:
            self.entries = decrypt_vault(blob["data"], key)
        except InvalidToken:
            return False
        self.key = key
        return True

    def save(self):
        blob = {
            "salt": base64.b64encode(self.salt).decode("utf-8"),
            "data": encrypt_vault(self.entries, self.key),
        }
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(blob, f)
        try:
            os.chmod(tmp, 0o600)  # sirf owner padh/likh sake
        except OSError:
            pass
        os.replace(tmp, self.path)  # atomic write, file corrupt nahi hogi

    def change_master(self, new_password: str):
        self.salt = os.urandom(16)
        self.key = derive_key(new_password, self.salt)
        self.save()

    # CRUD
    def add(self, site, username, password):
        self.entries[site.lower()] = {
            "site": site,
            "username": username,
            "password": password,
            "updated": datetime.now().strftime("%Y-%m-%d %H:%M"),
        }
        self.save()

    def get(self, site):
        return self.entries.get(site.lower())

    def delete(self, site) -> bool:
        if site.lower() in self.entries:
            del self.entries[site.lower()]
            self.save()
            return True
        return False

    def search(self, term):
        term = term.lower()
        return [e for k, e in self.entries.items() if term in k or term in e["username"].lower()]


# --------------------------------------------------------------------------
# Password utilities
# --------------------------------------------------------------------------
def generate_password(length: int = 16, symbols: bool = True) -> str:
    """Cryptographically secure random password (secrets module)."""
    length = max(length, 8)
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?")
    # har category se kam se kam ek character
    chars = [secrets.choice(p) for p in pools]
    alphabet = "".join(pools)
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def check_strength(password: str):
    """(score 0-5, label, suggestions) return karta hai."""
    score, tips = 0, []
    if len(password) >= 12:
        score += 1
    else:
        tips.append("Kam se kam 12 characters rakho")
    if any(c.islower() for c in password) and any(c.isupper() for c in password):
        score += 1
    else:
        tips.append("Upper aur lower dono case use karo")
    if any(c.isdigit() for c in password):
        score += 1
    else:
        tips.append("Numbers add karo")
    if any(c in string.punctuation for c in password):
        score += 1
    else:
        tips.append("Special symbols add karo")
    common = {"password", "123456", "qwerty", "admin", "welcome", "letmein", "iloveyou"}
    if password.lower() not in common and not any(c in password.lower() for c in common if len(c) > 5):
        score += 1
    else:
        tips.append("Common words/patterns avoid karo")
    labels = ["Very Weak", "Very Weak", "Weak", "Medium", "Strong", "Very Strong"]
    return score, labels[score], tips


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def ask_new_master() -> str:
    while True:
        pw = getpass.getpass("Naya master password set karo: ")
        score, label, tips = check_strength(pw)
        if score < 3:
            print(f"  Strength: {label}. Suggestions: {'; '.join(tips)}")
            continue
        if pw != getpass.getpass("Dobara enter karo: "):
            print("  Passwords match nahi hue, phir try karo.")
            continue
        return pw


def login(vault: Vault) -> bool:
    if not vault.exists():
        print("Koi vault nahi mila. Naya vault bana rahe hain...\n")
        vault.create(ask_new_master())
        print("Vault ban gaya!\n")
        return True
    for attempt in range(1, MAX_ATTEMPTS + 1):
        if vault.unlock(getpass.getpass("Master password: ")):
            print("Vault unlock ho gaya!\n")
            return True
        print(f"Galat password ({attempt}/{MAX_ATTEMPTS})")
    print("Bahut zyada galat attempts. Exit.")
    return False


def show_entry(e, reveal=True):
    print(f"  Site     : {e['site']}")
    print(f"  Username : {e['username']}")
    print(f"  Password : {e['password'] if reveal else '*' * 10}")
    print(f"  Updated  : {e['updated']}")


def menu():
    print("""
==== SECURE PASSWORD MANAGER ====
1. Password add karo
2. Password dekho
3. Saari entries list karo
4. Search
5. Update password
6. Delete entry
7. Password generate karo
8. Password strength check
9. Master password change karo
0. Exit""")
    return input("Choice: ").strip()


def main():
    vault = Vault()
    if not login(vault):
        sys.exit(1)

    while True:
        choice = menu()

        if choice == "1":
            site = input("Site/App: ").strip()
            if not site:
                print("Site name khali nahi ho sakta.")
                continue
            if vault.get(site) and input("Entry pehle se hai. Overwrite? (y/n): ").lower() != "y":
                continue
            user = input("Username/Email: ").strip()
            if input("Password auto-generate karu? (y/n): ").lower() == "y":
                try:
                    n = int(input("Length (default 16): ") or 16)
                except ValueError:
                    n = 16
                pw = generate_password(n)
                print(f"Generated: {pw}")
            else:
                pw = getpass.getpass("Password: ")
                _, label, tips = check_strength(pw)
                print(f"Strength: {label}" + (f" ({'; '.join(tips)})" if tips else ""))
            vault.add(site, user, pw)
            print("Saved (encrypted).")

        elif choice == "2":
            e = vault.get(input("Site: ").strip())
            show_entry(e) if e else print("Entry nahi mili.")

        elif choice == "3":
            if not vault.entries:
                print("Vault khali hai.")
            for e in sorted(vault.entries.values(), key=lambda x: x["site"].lower()):
                print(f"  - {e['site']:<25} {e['username']}")

        elif choice == "4":
            res = vault.search(input("Search term: ").strip())
            if not res:
                print("Kuch nahi mila.")
            for e in res:
                show_entry(e, reveal=False)
                print()

        elif choice == "5":
            site = input("Site: ").strip()
            e = vault.get(site)
            if not e:
                print("Entry nahi mili.")
                continue
            pw = getpass.getpass("Naya password (blank = auto-generate): ")
            if not pw:
                pw = generate_password()
                print(f"Generated: {pw}")
            vault.add(e["site"], e["username"], pw)
            print("Updated.")

        elif choice == "6":
            site = input("Site: ").strip()
            if input(f"'{site}' delete karna hai? (y/n): ").lower() == "y":
                print("Deleted." if vault.delete(site) else "Entry nahi mili.")

        elif choice == "7":
            try:
                n = int(input("Length (default 16): ") or 16)
            except ValueError:
                n = 16
            sym = input("Symbols chahiye? (y/n): ").lower() != "n"
            print("Password:", generate_password(n, sym))

        elif choice == "8":
            score, label, tips = check_strength(getpass.getpass("Password: "))
            print(f"Score: {score}/5 -> {label}")
            for t in tips:
                print("  *", t)

        elif choice == "9":
            if vault.unlock(getpass.getpass("Purana master password: ")):
                vault.change_master(ask_new_master())
                print("Master password change ho gaya.")
            else:
                print("Galat password.")

        elif choice == "0":
            print("Vault locked. Bye!")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nVault locked. Bye!")
