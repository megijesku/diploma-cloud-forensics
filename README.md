# Detektimi i aktiviteteve te paautorizuara permes analizes se log-eve

Kodi i temes se diplomes *"Studimi i sfidave te Cloud Forensics dhe implementimi i nje mekanizmi per detektimin e aktiviteteve te paautorizuara permes analizes se log-eve"*.

Projekti simulon nje mjedis AWS, gjeneron nje dataset sintetik me ngjarje CloudTrail (aktivitet normal, false positives dhe tre skenare sulmi), e analizon ate ne menyre forensike dhe aplikon rregulla automatike detektimi te lidhura me MITRE ATT&CK.

> Te gjitha te dhenat jane sintetike. Perdoruesit, IP-te dhe ngjarjet jane te simuluara.

## Struktura

```
scripts/
├── generate_logs.py      # 1. Gjeneron dataset-in CloudTrail (~850 ngjarje)
├── chain_of_custody.py   # 2. Llogarit hash SHA-256 per integritetin e proves
├── analyze_logs.py       # 3. Analiza forensike, timeline dhe raporti IoC
├── detector.py           # 4. Pese rregulla detektimi dhe metrikat (Precision, Recall, F1)
└── test_api_rate.py      # Test funksional i rregullit API_RATE (nuk modifikon dataset-in)
```

## Kerkesat

- Testuar me Python 3.12.3 ne Ubuntu 24.04 LTS
- Asnje librari e jashtme (vetem standard library)

## Ekzekutimi

```bash
cd scripts
python3 generate_logs.py
python3 chain_of_custody.py
python3 analyze_logs.py
python3 detector.py

# Opsionale: verifikimi i rregullit API_RATE
python3 test_api_rate.py
```

Output-et ruhen te `~/cloud_forensics/`:

| Skedari | Permbajtja |
|---|---|
| `logs/cloudtrail.json` | Dataset-i i gjeneruar |
| `evidence/hashes.txt` | Regjistri Chain of Custody (SHA-256) |
| `report/ioc_report.txt` | Raporti forensik me ngjarjet kritike dhe timeline |

Dataset-i gjenerohet me `random.seed(42)`, prandaj rezultatet jane te riprodhueshme.

## Skenaret e simuluar

| Skenari | Pershkrimi |
|---|---|
| Aktivitet normal | 5 punonjes me role te ndryshme gjate orarit te punes |
| False positives | Backup i nates, fjalekalim i gabuar, krijim llogarie per punonjes te ri |
| Attacker 1 (Tor) | Sulm i plote: brute force → recon → privilege escalation → exfiltration → fshirje gjurmesh |
| Attacker 2 (Scanner) | Brute force i deshtuar dhe testim emrash standarde |
| Attacker 3 (VPN) | Sulm i ngadalte me kredenciale te komprometuara, nen pragjet e detektimit |

## Rregullat e detektimit

| Rregulli | MITRE ATT&CK |
|---|---|
| Brute force (> 5 hyrje te deshtuara nga e njejta IP) | T1110 |
| Zinxhir sulmi (≥ 3 nga 4 faza) | T1078, T1098, T1530, T1562 |
| Aktivitet nate nga IP e panjohur | T1078 |
| Akses nga rajone AWS te panjohura (> 5 ngjarje jashte us-east-1) | — |
| API_RATE (> 20 thirrje API ne minute nga e njejta IP) | T1078 |

## Rezultatet

Ekzekutimi me `random.seed(42)` prodhon:

- 851 ngjarje: 728 normale, 33 potencialisht dykuptimeshe, 90 sulmi
- 8 alarme, te gjitha per IP sulmuese dhe asnje per IP legjitime
- Ne nivel skenari, te tre sulmuesit identifikohen nga te pakten nje rregull. Attacker 3 i shmanget ATTACK_CHAIN dhe identifikohet vetem nga FOREIGN_REGION.
- SHA-256 i `cloudtrail.json`: `e843d413da11945af2ffe4643140b9cbf2a462537efcad606c2073034c4a8d4c`

Nese hash-i qe merr pas ekzekutimit eshte i njejte me kete, dataset-i yt eshte identik me ate te analizuar ne punim.

**Shenim mbi metrikat:** TP dhe FP numerohen ne nivel alarmi, ndersa `fn = 1` eshte vendosur manualisht per Attacker 3. Precision, Recall dhe F1-Score jane tregues te procedures se implementuar dhe nuk jane metrika standarde te nje confusion matrix. Interpretimi i plote jepet ne kapitullin 4 te punimit.

## Standardet e referuara

- NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response
- ACPO Good Practice Guide for Digital Evidence
- MITRE ATT&CK for Cloud

## Autori

Megi Jesku
