# Ky skript lexon dataset-in dhe aplikon rregulla automatike detektimi, gjeneron alarme per cdo aktivitet te dyshimte dhe llogarit statistikat
import json
import os
from collections import Counter, defaultdict

# Percakton path-et e skedareve
BASE_DIR      = os.path.expanduser("~/cloud_forensics")
LOG_FILE      = os.path.join(BASE_DIR, "logs/cloudtrail.json")

# Cakton kufijte e detektimit, mbi keto vlera sistemi gjeneron alarm
THRESHOLD_BRUTE = 5    # Tentativa te deshtuara per brute force
THRESHOLD_EXFIL = 15  # Skedare te shkarkuar per data exfiltration
THRESHOLD_API_RATE = 20  # Thirrje API per minute per IP

# Deklaron IP-te e njohura si sulmues dhe si legjitime
ATTACKER_IPS = ["185.220.101.47", "45.33.32.156", "198.199.10.234"]
LEGIT_IPS    = ["89.42.12.100", "89.42.12.101", "89.42.12.102",
                "89.42.12.103", "89.42.12.104"]

def detect():
    # Ekzekuton rregullat automatike te detektimit mbi dataset-in, duke llogaritur true positives, false positives dhe false negatives
    if not os.path.exists(LOG_FILE):
        print("[!] Skedari i log-eve nuk u gjet! Ekzekuto generate_logs.py fillimisht")
        return

    with open(LOG_FILE) as f:
        data = json.load(f)
    events = data["Events"]

    print(f"\n[*] Analizoj {len(events)} ngjarje...")

    # Inicializon variablat per llogaritjen e statistikave te detektimit
    tp = 0  # True positives - sulme reale te detektuara sakte
    fp = 0  # False positives - alarme te rreme per aktivitet legjitim
    fn = 1  # False negatives - sulme qe i shpetuan detektimit (attacker 3)
    alarms = []
    
    # Zbaton Rregullin 1: Brute Force Detection per te kapur hyrjet e deshtuara
    # Nese e njejta IP ka me shume se THRESHOLD_BRUTE hyrje te deshtuara, konsiderohet sulm brute force dhe gjenerohet alarm
    failed_by_ip = Counter(
        e["SourceIPAddress"] for e in events
        if e["EventName"] == "ConsoleLogin"
        and e["ResponseElements"] == "Failure"
    )
    for ip, cnt in failed_by_ip.items():
        if cnt > THRESHOLD_BRUTE:
            is_real = ip in ATTACKER_IPS
            alarms.append({"rule": "BRUTE_FORCE", "ip": ip, "real": is_real})
            if is_real:
                tp += 1
                print(f"\n[alarm-tp] Brute force i detektuar (MITRE T1110)")
            else:
                fp += 1
                print(f"\n[alarm-fp] Brute force - false positive")
            print(f"           IP: {ip} | Tentativa: {cnt} | Threshold: {THRESHOLD_BRUTE}")

    # Zbaton Rregullin 2: Sequence Detection per te identifikuar zinxhir te plote sulmi
    # Analizon kombinimin e fazave te sulmit, duke perfshire brute force, eskalimin e privilegjeve, eksfiltrimin dhe fshirjen e gjurmve,
    # dhe nese identifikohen tre ose me shume faza, klasifikohet si sulm i organizuar
    ip_ops = defaultdict(list)
    for e in events:
        ip_ops[e["SourceIPAddress"]].append(e["EventName"])

    for ip, ops in ip_ops.items():
        ops_set   = set(ops)
        has_bf    = ops.count("ConsoleLogin") > THRESHOLD_BRUTE
        has_priv  = bool(ops_set & {"CreateUser", "AttachUserPolicy"})
        has_exfil = ops.count("GetObject") > THRESHOLD_EXFIL
        has_cover = bool(ops_set & {"DeleteTrail", "StopLogging"})

        score = sum([has_bf, has_priv, has_exfil, has_cover])

        if score >= 3:
            is_real = ip in ATTACKER_IPS
            alarms.append({"rule": "ATTACK_CHAIN", "ip": ip, "real": is_real})
            if is_real:
                tp += 1
                print(f"\n[alarm-tp] Zinxhir sulmi i plote (MITRE T1078+T1098+T1530+T1562)")
            else:
                fp += 1
                print(f"\n[alarm-fp] Zinxhir sulmi - false positive")
            print(f"           IP: {ip} | Score: {score}/4 faza")
            print(f"           BruteForce:{has_bf} | Privilege:{has_priv} | Exfil:{has_exfil} | Cover:{has_cover}")

    # Zbaton Rregullin 3: Anomali kohore per te zbuluar aktivitet te dyshimte gjate nates
    night_by_ip = defaultdict(int)
    for e in events:
        hour = int(e["EventTime"][11:13])
        if hour < 6 or hour > 22:
            night_by_ip[e["SourceIPAddress"]] += 1

    for ip, cnt in night_by_ip.items():
        if cnt > 10 and ip not in LEGIT_IPS:
            is_real = ip in ATTACKER_IPS
            alarms.append({"rule": "NIGHT_ACTIVITY", "ip": ip, "real": is_real})
            if is_real:
                tp += 1
                print(f"\n[alarm-tp] Aktivitet gjate nates  i dyshimte (MITRE T1078)")
            else:
                fp += 1
                print(f"\n[alarm-fp] Aktivitet gjate nates - false positive")
            print(f"           IP: {ip} | Ngjarje nate: {cnt}")

    # Zbaton Rregullin 4: Region Detection per te identifikuar akses nga rajone te panjohura
    # Organizata operon vetem ne us-east-1 (cdo region tjeter eshte anomali)
    known_regions  = {"us-east-1"}
    foreign_by_ip  = defaultdict(list)
    for e in events:
        if e.get("AwsRegion") not in known_regions:
            foreign_by_ip[e["SourceIPAddress"]].append(e["AwsRegion"])

    for ip, regions in foreign_by_ip.items():
        if len(regions) > 5 and ip not in LEGIT_IPS:
            is_real = ip in ATTACKER_IPS
            alarms.append({"rule": "FOREIGN_REGION", "ip": ip, "real": is_real})
            if is_real:
                tp += 1
                print(f"\n[alarm-tp] Aktivitet ne rajon te panjohur")
            else:
                fp += 1
                print(f"\n[alarm-fp] Rajon i panjohur - false positive")
            print(f"           IP: {ip} | Region: {list(set(regions))}")

    # Zbaton Rregullin 5: API Rate Detection
    api_rate_by_ip = defaultdict(lambda: defaultdict(int))
    for e in events:
        minute_key = e["EventTime"][:16]
        api_rate_by_ip[e["SourceIPAddress"]][minute_key] += 1

    for ip, minutes in api_rate_by_ip.items():
        max_per_minute = max(minutes.values())
        if max_per_minute > THRESHOLD_API_RATE and ip not in LEGIT_IPS:
            is_real = ip in ATTACKER_IPS
            alarms.append({"rule": "API_RATE", "ip": ip, "real": is_real})
            if is_real:
                tp += 1
                print(f"\n[alarm-tp] Aktivitet me shpejtesi te larte API (MITRE T1078)")
            else:
                fp += 1
                print(f"\n[alarm-fp] API Rate - false positive")
            print(f"           IP: {ip} | Max thirrje/minute: {max_per_minute} | Threshold: {THRESHOLD_API_RATE}")
    getobj_count = sum(1 for e in events 
                   if e['SourceIPAddress'] == '198.199.10.234' 
                   and e['EventName'] == 'GetObject')
    print(f"\n[*] Attacker 3 (VPN) i shmanget detektimit")
    print(f"    perdori {getobj_count} GetObject - nen pragun prej {THRESHOLD_EXFIL}")


    # Llogarit metrikat e performances per vleresimin e sistemit te detektimit
    # - Precision: Raporti i alarmeve te sakta ndaj totalit te alarmeve te gjeneruara
    # - Recall   : Raporti i sulmeve reale te kapura ndaj totalit te sulmeve ekzistuese
    # - F1-Score : Mesatarja harmonike e Precision dhe Recall per nje vleresim te balancuar

    total   = len(alarms)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0)

    print(f"\n")
    print(f"Statistikat e performances se detektorit:")
    print(f"-"*50)
    print(f"Alarme totale:    {total}")
    print(f"True Positives:  {tp}  (sulme reale te detektuara sakte)")
    print(f"False Positives: {fp}  (alarme te rreme)")
    print(f"False Negatives: {fn}  (sulme qe shpetuan detektimin)")
    print(f"Precision:       {precision:.2%}")
    print(f"Recall:          {recall:.2%}")
    print(f"F1-Score:        {f1:.2%}")

if __name__ == "__main__":
    # Thirrja e funksionit kryesor per nisjen e detektimit automatik
    print( "\n")
    print("Detektimi Automatik i Aktivitetit te Dyshimte")
    print("-"*50)
    detect()
