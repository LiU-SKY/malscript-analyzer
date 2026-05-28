# backend/security/attack_mapper.py
from __future__ import annotations
from security.schemas import MitreTechnique

ATT_AND_CK_BASE = "https://attack.mitre.org/techniques"

TECHNIQUE_CATALOG: dict[str, dict] = {
    "T1059":     {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell",                        "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell",             "tactic": "Execution"},
    "T1059.005": {"name": "Visual Basic",                      "tactic": "Execution"},
    "T1059.006": {"name": "Python",                            "tactic": "Execution"},
    "T1059.007": {"name": "JavaScript",                        "tactic": "Execution"},
    "T1203":     {"name": "Exploitation for Client Execution", "tactic": "Execution"},
    "T1027":     {"name": "Obfuscated Files or Information",   "tactic": "Defense Evasion"},
    "T1027.001": {"name": "Binary Padding",                    "tactic": "Defense Evasion"},
    "T1027.010": {"name": "Command Obfuscation",               "tactic": "Defense Evasion"},
    "T1140":     {"name": "Deobfuscate/Decode Files or Info",  "tactic": "Defense Evasion"},
    "T1562":     {"name": "Impair Defenses",                   "tactic": "Defense Evasion"},
    "T1053.005": {"name": "Scheduled Task",                    "tactic": "Persistence"},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder","tactic": "Persistence"},
    "T1543.003": {"name": "Windows Service",                   "tactic": "Persistence"},
    "T1548.002": {"name": "Bypass User Account Control",       "tactic": "Privilege Escalation"},
    "T1055":     {"name": "Process Injection",                 "tactic": "Privilege Escalation"},
    "T1055.001": {"name": "Dynamic-link Library Injection",    "tactic": "Privilege Escalation"},
    "T1055.012": {"name": "Process Hollowing",                 "tactic": "Privilege Escalation"},
    "T1003":     {"name": "OS Credential Dumping",             "tactic": "Credential Access"},
    "T1003.001": {"name": "LSASS Memory",                      "tactic": "Credential Access"},
    "T1555":     {"name": "Credentials from Password Stores",  "tactic": "Credential Access"},
    "T1082":     {"name": "System Information Discovery",      "tactic": "Discovery"},
    "T1083":     {"name": "File and Directory Discovery",      "tactic": "Discovery"},
    "T1057":     {"name": "Process Discovery",                 "tactic": "Discovery"},
    "T1016":     {"name": "System Network Configuration Discovery", "tactic": "Discovery"},
    "T1033":     {"name": "System Owner/User Discovery",       "tactic": "Discovery"},
    "T1071":     {"name": "Application Layer Protocol",        "tactic": "Command and Control"},
    "T1071.001": {"name": "Web Protocols",                     "tactic": "Command and Control"},
    "T1095":     {"name": "Non-Application Layer Protocol",    "tactic": "Command and Control"},
    "T1105":     {"name": "Ingress Tool Transfer",             "tactic": "Command and Control"},
    "T1572":     {"name": "Protocol Tunneling",                "tactic": "Command and Control"},
    "T1048":     {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1041":     {"name": "Exfiltration Over C2 Channel",      "tactic": "Exfiltration"},
    "T1486":     {"name": "Data Encrypted for Impact",         "tactic": "Impact"},
    "T1490":     {"name": "Inhibit System Recovery",           "tactic": "Impact"},
    "T1485":     {"name": "Data Destruction",                  "tactic": "Impact"},
}


def enrich_mitre_techniques(techniques: list[MitreTechnique]) -> list[MitreTechnique]:
    seen: set[str] = set()
    result: list[MitreTechnique] = []
    for tech in techniques:
        tid = tech.technique_id.upper().strip()
        if not tid or tid in seen:
            continue
        seen.add(tid)
        catalog_entry = TECHNIQUE_CATALOG.get(tid)
        name   = catalog_entry["name"]   if catalog_entry else tech.name
        tactic = catalog_entry["tactic"] if catalog_entry else tech.tactic
        result.append(MitreTechnique(
            technique_id=tid,
            name=name,
            tactic=tactic,
            url=_build_url(tid),
        ))
    return result


def _build_url(technique_id: str) -> str:
    parts = technique_id.split(".")
    if len(parts) == 2:
        return f"{ATT_AND_CK_BASE}/{parts[0]}/{parts[1]}"
    return f"{ATT_AND_CK_BASE}/{parts[0]}"
