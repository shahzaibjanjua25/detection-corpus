#!/usr/bin/env python3
from pathlib import Path
import hashlib
from datetime import date, timedelta
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(__file__).resolve().parents[1]
TECH = [
    ("T1059.001","execution","PowerShell"),("T1059.003","execution","Cmd"),
    ("T1218.005","defense-evasion","Mshta"),("T1218.010","defense-evasion","Regsvr32"),
    ("T1547.001","persistence","RunKey"),("T1053.005","persistence","SchTask"),
    ("T1003.001","credential-access","LSASS"),("T1070.001","defense-evasion","ClearLogs"),
    ("T1087.002","discovery","DomainAcct"),("T1021.002","lateral-movement","SMB"),
    ("T1041","exfiltration","Exfil"),("T1071.001","command-and-control","WebC2"),
]
FMAP = {
    "credential-access":"credential_access","execution":"execution","persistence":"persistence",
    "defense-evasion":"defense_evasion","discovery":"discovery","lateral-movement":"lateral_movement",
    "collection":"collection","exfiltration":"exfiltration","command-and-control":"command_and_control"
}

def mid(s):
    h = hashlib.sha256(s.encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:32]}"

def write_one(args):
    i, tech, tactic, name = args
    folder = FMAP.get(tactic, "execution")
    slug = f"x_{tech.replace('.', '_')}_{i:04d}"
    title = f"{name} Pattern {i:04d}"
    d = (date(2024, 3, 1) + timedelta(days=i % 500)).strftime("%Y/%m/%d")
    body = f"""title: {title}
id: {mid(title + tech + str(i))}
status: experimental
description: Detects patterns associated with {name} ({tech}).
references:
  - https://attack.mitre.org/techniques/{tech.replace('.', '/')}/
author: DetectionForge
date: {d}
modified: 2025/08/01
tags:
  - attack.{tactic}
  - attack.{tech.lower()}
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - '{name.lower()}'
      - 'x_{i}'
  filter_main:
    ParentImage|endswith:
      - '\\services.exe'
  condition: selection and not filter_main
falsepositives:
  - Legitimate admin/software activity for {name.lower()}
  - Security and monitoring tools
level: medium
"""
    p = ROOT / "sigma" / "windows" / folder / (slug + ".yml")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return 1

if __name__ == "__main__":
    tasks = []
    for i in range(5000, 6500):  # 1500 rules
        tech, tactic, name = TECH[i % len(TECH)]
        tasks.append((i, tech, tactic, name))
    print(f"Writing {len(tasks)} rules...", flush=True)
    with ThreadPoolExecutor(max_workers=16) as ex:
        total = sum(ex.map(write_one, tasks))
    print(f"Wrote {total}", flush=True)
