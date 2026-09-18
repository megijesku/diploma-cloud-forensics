# Moduli per gjenerimin e vleres hash SHA-256 te skedarit te log-eve, duke garantuar integritetin e provave digjitale sipas udhezimeve 
# te standardeve NIST SP 800-86 dhe ACPO Guidelines per Chain of Custody.

import hashlib
import os
from datetime import datetime, timezone

# Konfigurimi i shtigjeve per skedaret e sistemit te provave
BASE_DIR      = os.path.expanduser("~/cloud_forensics")
LOG_FILE      = os.path.join(BASE_DIR, "logs/cloudtrail.json")
EVIDENCE_FILE = os.path.join(BASE_DIR, "evidence/hashes.txt")

def chain_of_custody():
    # Llogaritja e vleres kriptografike SHA-256 per skedarin e log-eve
    # Vetia e funksionit hash siguron qe cdo ndryshim apo modifikim i skedarit
    # prodhon nje vlere te ndryshme, duke garantuar se provat nuk jane manipuluar
    # Verifikimi i pranise se skedarit te log-eve perpara perpunimit
    if not os.path.exists(LOG_FILE):
        print("[!] Skedari i log-eve nuk u gjet! Ekzekuto generate_logs.py fillimisht")
        return

    # Llogaritja e vleres hash SHA-256 per permbajtjen binare te skedarit
    sha256 = hashlib.sha256()
    with open(LOG_FILE, "rb") as f:
        sha256.update(f.read())
    file_hash = sha256.hexdigest()

    # Regjistrimi i metadﺗave (timestamp i verifikimit dhe identiteti i analistit)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    analyst   = "Megi"

    # Ruajtja e rekordit te Chain of Custody ne skedarin e provave
    os.makedirs(os.path.dirname(EVIDENCE_FILE), exist_ok=True)
    with open(EVIDENCE_FILE, "a") as f:
        f.write(f"SHA-256:    {file_hash}\n")
        f.write(f"Skedari:    {LOG_FILE}\n")
        f.write(f"Analist:    {analyst}\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write("-"*60 + "\n")

    print(f"\n[+] SHA-256:     {file_hash}")
    print(f"[+] Skedari:     {LOG_FILE}")
    print(f"[+] Analist:     {analyst}")
    print(f"[+] Timestamp:  {timestamp}")
    print(f"[+] U ruajt ne: {EVIDENCE_FILE}")
    print(f"\n[*] Cdo ndryshim i skedarit prodhon hash te ndryshem")
    print(f"[*] Ky hash sherben si prove e integritetit te log-eve")


if __name__ == "__main__":
    # Ekzekutimi i procedures per ruajtjen e zinxhirit te trashegimise se provave (Chain of Custody)
    print("\n")
    print("Chain of Custody - Integritet i Provave Forensik (NIST SP 800-86)")
    print("."*67)
    chain_of_custody()
