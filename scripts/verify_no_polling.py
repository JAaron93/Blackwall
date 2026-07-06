#!/usr/bin/env python3
import os
import re
import sys
from pathlib import Path

def main():
    src_dir = Path("src")
    if not src_dir.exists():
        print("src directory not found. Must run from project root.")
        sys.exit(1)

    patterns = [
        (re.compile(r"asyncio\.sleep\s*\("), "asyncio.sleep()"),
        (re.compile(r"time\.sleep\s*\("), "time.sleep()"),
        (re.compile(r"asyncio\.create_task\(.*name=['\"].*poll.*['\"]"), "asyncio.create_task with 'poll' name"),
    ]

    approved_locations = {
        "blackwall/resolver.py",
        "blackwall/mcp/gti_client.py",
        "blackwall/interception.py",
        "blackwall/middleware/context_hygiene.py",
        "blackwall/mcp/gti_budget_tracker.py",
    }

    violations = []

    for root, _, files in os.walk(src_dir):
        for file in files:
            if not file.endswith(".py"):
                continue

            file_path = Path(root) / file
            rel_path = file_path.relative_to(src_dir).as_posix()
            
            if rel_path in approved_locations:
                continue

            with open(file_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    for pattern, desc in patterns:
                        if pattern.search(line):
                            violations.append(f"{file_path}:{line_num} - Found {desc}: {line.strip()}")

    if violations:
        print("POLLING PATTERNS DETECTED! Event-driven invariant violated.")
        for violation in violations:
            print(violation)
        sys.exit(1)
    
    print("Event-driven invariant verified: No polling patterns found in analysis path.")
    sys.exit(0)

if __name__ == "__main__":
    main()
