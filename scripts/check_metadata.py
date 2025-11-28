#!/usr/bin/env python3
"""Quick metadata completeness check for Sigma rules."""
import sys
from pathlib import Path
import re

REQUIRED = ["title:", "id:", "status:", "description:", "author:", "date:", "tags:", "logsource:", "detection:", "falsepositives:", "level:"]

def check_file(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    missing = [f for f in REQUIRED if f not in text]
    fps = re.findall(r"^\s*-\s+.+$", text, re.M)
    if text.count("falsepositives:") and len(fps) < 2:
        missing.append("falsepositives (<2 entries)")
    return missing

def main():
    root = Path(__file__).resolve().parents[1]
    sigma_files = list(root.glob("sigma/**/*.yml"))
    errors = 0
    for f in sorted(sigma_files):
        miss = check_file(f)
        if miss:
            print(f"[FAIL] {f.relative_to(root)}: missing {miss}")
            errors += 1
        else:
            print(f"[OK]   {f.relative_to(root)}")
    print(f"\nChecked {len(sigma_files)} files, {errors} failures")
    return 1 if errors else 0

if __name__ == "__main__":
    sys.exit(main())
