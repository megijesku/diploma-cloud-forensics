# Ky skript lexon dataset-in e gjeneruar dhe kryen analizen forensike, identifikon aktivitet te dyshimte, nderton timeline dhe ruan raportin
import json
import os
from datetime import datetime, timezone
from collections import Counter, defaultdict

# Path-et e skedareve (duhet te perputhen me generate_logs.py)
BASE_DIR      = os.path.expanduser("~/cloud_forensics")
LOG_FILE      = os.path.join(BASE_DIR, "logs/cloudtrail.json")
REPORT_FILE   = os.path.join(BASE_DIR, "report/ioc_report.txt")

# IP-te e sulmuesve (perdoren per te etiketuar ngjarjet ne raport)
ATTACKER_IPS = ["185.220.101.47", "45.33.32.156", "198.199.10.234"]
LEGIT_IPS    = ["89.42.12.100", "89.42.12.101", "89.42.12.102",
                "89.42.12.103", "89.42.12.104"]

# Operacionet qe konsiderohen kritike dhe kerkojne hetim
CRITICAL_OPS = [
    "CreateUser", "AttachUserPolicy", "CreateAccessKey",
    "DeleteTrail", "StopLogging", "PutBucketPolicy",
    "CreateRole", "AttachRolePolicy", "RunInstances",
]

def analyze_logs():
    # Lexon dataset-in dhe kryen analizen forensike, rezultatet shfaqen ne terminal dhe ruhen ne ioc_report.txt
    # Kontrollon nese skedari ekziston perpara se te lexohet
    if not os.path.exists(LOG_FILE):
        print("[!] Skedari i log-eve nuk u gjet! Ekzekuto generate_logs.py fillimisht")
        return

    with open(LOG_FILE) as f:
        data = json.load(f)
    events = data["Events"]

    print(f"\n[*] Dataset i ngarkuar: {len(events)} ngjarje totale")

    # Statistika baze te dataset-it
    ip_counter   = Counter(e["SourceIPAddress"] for e in events)
    user_counter = Counter(e["Username"] for e in events)
    op_counter   = Counter(e["EventName"] for e in events)

    print(f"\nStatistika Baze ")
    print("-"*50)
    print(f"IP unike:         {len(ip_counter)}")
    print(f"Perdorues unik:   {len(user_counter)}")
    print(f"Operacione unike: {len(op_counter)}")

    # Analiza e hyrjeve te deshtuara, identifikon brute force, grupimi i hyrjeve te deshtuara sipas ip per te gjetur sulmin
    failed = [e for e in events
              if e["EventName"] == "ConsoleLogin"
              and e["ResponseElements"] == "Failure"]

    failed_by_ip = Counter(e["SourceIPAddress"] for e in failed)

    print(f"\nHyrjet e Deshtuara ")
    print("-"*56)
    print(f"Totale: {len(failed)} | IP me probleme: {len(failed_by_ip)}")
    for ip, cnt in failed_by_ip.most_common(5):
        # Shenon nese ip eshte e njohur si sulmues
        flag = " <- Dyshimte" if ip in ATTACKER_IPS else " (normale)"
        print(f"    {ip:22s} -> {cnt:3d} tentativa{flag}")

    # Analiza e aktivitetit per ore, identifikon anomali kohore
    # Aktivitet i larte naten (00:00-06:00) eshte shenje sulmi
    hourly = defaultdict(int)
    for e in events:
        hour = int(e["EventTime"][11:13])
        hourly[hour] += 1

    print(f"\nAktiviteti per Ore ")
    print("-"*50)
    for hour in range(24):
        count = hourly.get(hour, 0)
        flag  = " <- Anomali Kohore" if hour < 6 and count > 20 else ""
        print(f"    {hour:02d}:00  {count:4d}{flag}")
    
    # Identifikon ngjarjet kritike dhe i grupon sipas ip, nese nje ip e panjohur kryen operacione kritike = alarm
    crit_events = [e for e in events if e["EventName"] in CRITICAL_OPS]

    print(f"\nNgjarjet Kritike ({len(crit_events)} gjithsej) ")
    print("-"*72)
    crit_by_ip = defaultdict(list)
    for e in crit_events:
        crit_by_ip[e["SourceIPAddress"]].append(e["EventName"])

    for ip, ops in sorted(crit_by_ip.items(), key=lambda x: -len(x[1])):
        flag = " [Legjitim]" if ip in LEGIT_IPS else " [Dyshimte]"
        print(f"    IP: {ip}{flag}")
        for op, cnt in Counter(ops).most_common():
            print(f"        {op:30s} x{cnt}")

    # Timeline i sulmit kryesor (rendit ngjarjet kronologjikisht), kjo ndihmon per te kuptuar sekuencen e sulmit hap pas hapi
    # Shfaq vetem ngjarjet kryesore te sulmit, jo te gjitha GetObject
    print(f"\nTimeline i sulmit kryesor (ngjarjet kyce):")
    atk_events = [e for e in events
                  if e["SourceIPAddress"] == "185.220.101.47"]

    prev_op = None
    for e in atk_events:
        result = "OK  " if e["ResponseElements"] == "Success" else "FAIL"
        if e["EventName"] == "GetObject":
            if prev_op != "GetObject":
                print(f"    {e['EventTime']} | {result} | GetObject x35 (data exfiltration) | {e['Username']}")
        else:
            print(f"    {e['EventTime']} | {result} | {e['EventName']:30s} | {e['Username']}")
        prev_op = e["EventName"]
   
    # Gjenerimi dhe ruajtja e raportit forensik ne skedar teksti per dokumentim dhe analize te metejshme
    os.makedirs(os.path.dirname(REPORT_FILE), exist_ok=True)
    with open(REPORT_FILE, "w") as f:
        f.write("Raporti Forensik: Cloud Log Analysis\n")
        f.write(f"Data: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
        f.write(f"Dataset: {len(events)} ngjarje totale\n\n")
        f.write(" Ngjarjet kritike: \n")
        for e in crit_events:
            f.write(f"{e['EventTime']} | {e['EventName']:30s} | {e['Username']:20s} | {e['SourceIPAddress']}\n")
        f.write("\n Timeline i sulmit kryesor: \n")
        for e in atk_events:
            f.write(f"{e['EventTime']} | {e['EventName']:30s} | {e['Username']}\n")

    print(f"\n[+] Raporti u ruajt: {REPORT_FILE}")


if __name__ == "__main__":
    # Ekzekutimi i procesit kryesor per nisjen e analizes forensike
    print("\n")
    print("Analiza Forensike e Dataset-it")
    print("-"*50)
    analyze_logs()
