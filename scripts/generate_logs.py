# Tema e Diplomes - Studimi i sfidave te Cloud Forensics dhe implementimi i nje mekanizmi per
# detektimin e aktiviteteve te paautorizuara  permes analizes se log-eve
# Ky skript gjeneron nje dataset me 800+ ngjarje CloudTrail, i analizon ato dhe detekton aktivitet te dyshimte automatikisht
import json
import hashlib
import os
import random
from datetime import datetime, timedelta, timezone
from collections import Counter, defaultdict

# random.seed(42) siguron qe cdo here qe ekzekutoj skriptin te marr te njejtat rezultate
random.seed(42)

# Path-et ku do te ruhen skedaret e projektit
BASE_DIR      = os.path.expanduser("~/cloud_forensics")
LOG_FILE      = os.path.join(BASE_DIR, "logs/cloudtrail.json")
REPORT_FILE   = os.path.join(BASE_DIR, "report/ioc_report.txt")
EVIDENCE_FILE = os.path.join(BASE_DIR, "evidence/hashes.txt")

# Lista e punonjesve te kompanise qe perdorin sistemin cdo dite
# Secili ka nje IP fikse te rrjetit intern dhe nje rol te caktuar
# admin = akses i plote | developer = akses i kufizuar | analyst = lexim dhe raportim | readonly = vetem lexim
LEGIT_USERS = [
    {"name": "alice.smith",  "ip": "89.42.12.100", "role": "admin"},
    {"name": "bob.jones",    "ip": "89.42.12.101", "role": "developer"},
    {"name": "carol.white",  "ip": "89.42.12.102", "role": "analyst"},
    {"name": "david.brown",  "ip": "89.42.12.103", "role": "readonly"},
    {"name": "eve.martin",   "ip": "89.42.12.104", "role": "developer"},
]

# Lista e sulmuesve te simuluar - personazhe fiktive me IP te rreme
# Ne realitet keto IP jane te dokumentuara si burime sulmi ne internet
# Tor Exit Node = fsheh identitetin | Scanner = kerkon dobesi | VPN = maskim
ATTACKERS = [
    {"name": "attacker_1", "ip": "185.220.101.47", "type": "Tor Exit Node"},
    {"name": "attacker_2", "ip": "45.33.32.156",   "type": "Known Scanner"},
    {"name": "attacker_3", "ip": "198.199.10.234",  "type": "VPN/Proxy"},
]

# Operacionet qe punonjesit e zakonshem kryejne cdo dite ne sistem
# Keto konsiderohen aktivitet normal dhe nuk shkaktojne alarm
NORMAL_OPS = [
    "DescribeInstances",       # shikon instancat EC2 ekzistuese
    "ListBuckets",               # liston bucket-et S3
    "GetObject",                 # shkarkon nje skedar nga S3
    "PutObject",                 # ngarkon nje skedar ne S3
    "DescribeSecurityGroups",    # shikon rregullat e firewall-it
    "ListUsers",                 # liston perdoruesit e sistemit
    "GetCallerIdentity",         # kontrollon cilin user eshte i loguar
    "DescribeVpcs",              # shikon rrjetat virtuale
    "ListRoles",                 # liston rolet IAM
    "GetBucketPolicy",           # lexon politiken e nje bucket-i
    "DescribeSubnets",           # shikon nen-rrjetat
    "ListFunctions",             # liston funksionet Lambda
]

# Operacionet kritike qe mund te tregojne nje sulm ne progres
# Nese kryhen nga nje IP e panjohur keto shkaktojne alarm te menjehereshem
CRITICAL_OPS = [
    "CreateUser",                    # krijon nje user te ri (rrezik backdoor)
    "AttachUserPolicy",              # i jep privilegje nje useri (rrezik eskalimi)
    "CreateAccessKey",               # krijon celes aksesi (rrezik vjedhje)
    "DeleteTrail",                   # fshin gjurmet e auditimit (fshehje sulmi)
    "StopLogging",                   # ndal regjistrim (fshehje sulmi)
    "PutBucketPolicy",               # modifikon aksesin ne S3 (rrezik rrjedhje)
    "CreateRole",                    # krijon rol te ri (rrezik eskalimi)
    "AttachRolePolicy",              # i jep privilegje nje roli (rrezik eskalimi)
    "RunInstances",                  # nis makina virtuale (rrezik kriptominues)
    "AuthorizeSecurityGroupIngress", # hap porte ne firewall (rrezik aksesi)
]


# Funksionet ndihmese

def make_timestamp(base_time, offset_minutes, jitter_seconds=0):
    # Krijon nje timestamp realist per cdo ngjarje
    # Jitter shton nje vonese te vogel te rastesishme per shperndarje reale
    jitter = random.randint(-jitter_seconds, jitter_seconds)
    t = base_time + timedelta(minutes=offset_minutes, seconds=jitter)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")

def make_event(timestamp, name, user, ip, success=True, region=None):
    # Krijon nje ngjarje te strukturuar ne formatin CloudTrail, cdo ngjarje perben nje veprim te kryer nga user-i ne sistem
    regions = ["us-east-1", "eu-west-1", "ap-southeast-1"]
    return {
        "EventTime":        timestamp,
        "EventName":        name,
        "Username":         user,
        "SourceIPAddress":  ip,
        "AwsRegion":        region or random.choice(regions),
        "ResponseElements": "Success" if success else "Failure",
        "EventType":        "AwsApiCall",
    }


# Gjenerimi automatik i dataset-it
def generate_logs():
    # Ky funksion gjeneron automatikisht ngjarjet CloudTrail duke perfshire
    # aktivitetin normal, sulmet e simuluara dhe rastet e false positives.

    events = []  # Lista ku grumbullohen te gjitha ngjarjet e gjeneruara

    # Data fillestare e simulimit: E hene, 18 Mars 2025, ora 00:00.
    base_day = datetime(2025, 3, 18, 0, 0, 0)

    # Aktiviteti normal i punonjesve gjate oreve te punes (08:00 - 18:00)
    print("[*] Duke gjeneruar aktivitetin normal te punonjesve...")

    for user_info in LEGIT_USERS:
        work_start = 8 * 60 + random.randint(0, 90)
        num_ops = random.randint(120, 160)

        for i in range(num_ops):
            offset = work_start + (i * (8 * 60 / num_ops))
            ts = make_timestamp(base_day, offset, jitter_seconds=120)
            op = random.choice(NORMAL_OPS)
            success = random.random() > 0.05
            events.append(make_event(ts, op, user_info["name"],
                                   user_info["ip"], success, "us-east-1"))

    print(f"    [+] {len(events)} ngjarje normale te gjeneruara")
    normal_count = len(events)

    # Shtimi i rasteve te false positives per te testuar ndjeshmerine e detektorit
    print("[*] Duke shtuar false positives...")

    fp_start = len(events)

    # Backup automatik i nates (alice.smith), i ngjashem me nje aktivitet te dyshimte por i planifikuar nga kompania
    backup_start = 2 * 60
    for i in range(25):
        ts = make_timestamp(base_day, backup_start + i * 0.5,
                            jitter_seconds=10)
        events.append(make_event(ts, "GetObject", "alice.smith",
                                 "89.42.12.100", True, "us-east-1"))

    # 4 tentativa te deshtuara te fjalekalimit nga bob.jones, te pasuara nga hyrje e suksesshme pasi behet reset fjalekalimi
    for i in range(4):
        ts = make_timestamp(base_day, 8 * 60 + i * 2, jitter_seconds=30)
        events.append(make_event(ts, "ConsoleLogin", "bob.jones",
                                 "89.42.12.101", False))
    ts = make_timestamp(base_day, 8 * 60 + 10)
    events.append(make_event(ts, "ConsoleLogin", "bob.jones",
                                 "89.42.12.101", True))

    # alice.smith krijon llogari per punonjes te ri, operacion legjitim por duket si privilege escalation per detektorin
    for op in ["CreateUser", "AttachUserPolicy", "CreateAccessKey"]:
        ts = make_timestamp(base_day, 10 * 60 + random.randint(0, 30))
        events.append(make_event(ts, op, "alice.smith",
                                 "89.42.12.100", True))


    fp_count = len(events) - fp_start
    print(f"    [+] {fp_count} false positives te shtuar")

    # Simulimi i sulmit kryesor per Attacker 1 (Tor Exit Node)
    # Ky sulmues kryen nje sulm te plote me te gjitha fazat, bazuar ne MITRE ATT&CK Framework

    print("[*] Duke simuluar sulmin kryesor (Attacker 1 - Tor)...")
    
    # Sulmi fillon ne 02:00 bazuar te (base_day)
    atk1 = ATTACKERS[0]
    a1_base = base_day + timedelta(hours=2)

    # Faza 1: Brute Force (tentativa te deshtuara hyrjeje)
    for i in range(12):
        ts = make_timestamp(a1_base, i * 0.8, jitter_seconds=15)
        events.append(make_event(ts, "ConsoleLogin", "admin",
                                 atk1["ip"], False))

    # Faza 2: Hyrje e suksesshme pas gjetjes se kredencialeve
    ts = make_timestamp(a1_base, 11)
    events.append(make_event(ts, "ConsoleLogin", "admin",
                             atk1["ip"], True))

    # Faza 3: Reconnaissance (zbulim i burimeve cloud)
    recon_ops = ["ListUsers", "ListBuckets", "DescribeInstances",
                 "GetCallerIdentity", "ListRoles",
                 "DescribeSecurityGroups", "ListFunctions",
                 "DescribeVpcs", "GetAccountSummary"]
    for i, op in enumerate(recon_ops):
        ts = make_timestamp(a1_base, 13 + i * 0.5, jitter_seconds=10)
        events.append(make_event(ts, op, "admin", atk1["ip"], True))

    # Faza 4: Privilege Escalation (krijim backdoori me te drejta administrative)
    priv_ops = ["CreateUser", "AttachUserPolicy", "CreateAccessKey",
                "CreateRole", "AttachRolePolicy"]
    for i, op in enumerate(priv_ops):
        ts = make_timestamp(a1_base, 20 + i, jitter_seconds=5)
        events.append(make_event(ts, op, "admin", atk1["ip"], True))

    # Faza 5: Data Exfiltration (vjedhje e skedareve nga S3)
    for i in range(35):
        ts = make_timestamp(a1_base, 28 + i * 0.4, jitter_seconds=8)
        events.append(make_event(ts, "GetObject", "svc-backup-01",
                                 atk1["ip"], True))

    # Faza 6: Mbulim gjurmesh (fshirje e regjistrave te auditimit)
    cover_ops = ["DeleteTrail", "StopLogging",
                 "DeleteLogGroup", "PutBucketPolicy"]
    for i, op in enumerate(cover_ops):
        ts = make_timestamp(a1_base, 50 + i * 2, jitter_seconds=5)
        events.append(make_event(ts, op, "svc-backup-01",
                                 atk1["ip"], True))

    print(f"    [+] Sulmi 1 (Tor): {len([e for e in events if e['SourceIPAddress'] == atk1['ip']])} ngjarje")

    # Simulimi i sulmit te pjesshem per Attacker 2 (Known Scanner)
    print("[*] Duke simuluar sulmin e pjesshem (Attacker 2 - Scanner)...")

    atk2 = ATTACKERS[1]
    # Fillimi i aktivitetit ne oren 03:30, ne nje interval kohor pasues nga skenari i meparshem
    a2_base = base_day + timedelta(hours=3, minutes=30)
 
    # Tentativa Brute Force te bllokuara ne fazen e pare per shkak te kredencialeve te pasakta
    for i in range(8):
        ts = make_timestamp(a2_base, i * 1.2, jitter_seconds=20)
        events.append(make_event(ts, "ConsoleLogin", "admin",
                                 atk2["ip"], False))

    # Testim i emrave standarde te perdoruesve
    for user in ["root", "administrator", "test", "backup"]:
        ts = make_timestamp(a2_base, random.randint(10, 20),
                            jitter_seconds=30)
        events.append(make_event(ts, "ConsoleLogin", user,
                                 atk2["ip"], False))

    print(f"    [+] Sulmi 2 (Scanner): {len([e for e in events if e['SourceIPAddress'] == atk2['ip']])} ngjarje")

    # Simulimi i sulmit te avancuar per Attacker 3 (VPN/Proxy)
    # Ky sulmues paraqet rrezik me te larte pasi vepron ne menyre diskrete,
    # duke shmangur detektimin dhe duke demonstruar kufizimet e sistemeve rule-based.

    print("[*] Duke simuluar sulmin e avancuar (Attacker 3 - VPN)...")

    atk3 = ATTACKERS[2]
    # Fillimi i aktivitetit gjate oreve te punes per t'u pershtatur me trafikun legjitim dhe per te shmangur dyshimet
    a3_base = base_day + timedelta(hours=14)

    # Hyrje e suksesshme duke shfrytezuar kredenciale te komprometuara me pare
    ts = make_timestamp(a3_base, 0)
    events.append(make_event(ts, "ConsoleLogin", "carol.white",
                             atk3["ip"], True))

    # Zbulim i ngadaltshem (reconnaissance) per te shmangur alarmet e bazuara ne shpejtesi (rate-based)
    for i, op in enumerate(["ListBuckets", "GetCallerIdentity",
                            "ListUsers"]):
        ts = make_timestamp(a3_base, 5 + i * 10, jitter_seconds=60)
        events.append(make_event(ts, op, "carol.white", atk3["ip"], True))

    # Data Exfiltration per vetem 8 skedare. Veprimi kryhet qellimisht nen pragun (threshold) prej 15 kerkesash,
    # per te mbajtur aktivitetin nen pragun e rregullit perkates
    for i in range(8):
        ts = make_timestamp(a3_base, 35 + i * 5, jitter_seconds=120)
        events.append(make_event(ts, "GetObject", "carol.white",
                                 atk3["ip"], True))

    print(f"    [+] Sulmi 3 (VPN): {len([e for e in events if e['SourceIPAddress'] == atk3['ip']])} ngjarje")

    # Renditja kronologjike e ngjarjeve sipas timestamps per analizen forensike
    events.sort(key=lambda x: x["EventTime"])

    # Ruajtja e dataset-it te gjeneruar ne formatin JSON
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "w") as f:
        json.dump({"Events": events, "TotalCount": len(events)}, f, indent=2)

    print(f"\n[+] Dataset Total: {len(events)} ngjarje te gjeneruara")
    print(f"    - Aktivitet normal:    {normal_count}")
    print(f"    - False positives:     {fp_count}")
    print(f"    - Ngjarje sulmuesish: {len(events) - normal_count - fp_count}")
    print(f"[+] Skedari u ruajt: {LOG_FILE}")

    return events

# Ekzekutimi i skriptit kur thirret direkt
if __name__ == "__main__":
    print("\n")
    print("Gjenerimi i dataset-it CloudTrail")
    print("-"*50)
    generate_logs()

