#!/usr/bin/env python3
"""Fail the build if any Autobahn case did not pass.

The suite writes a report and exits 0 regardless of results, so without this
a totally broken server produces a green build.
"""
import json
import sys
from collections import Counter

PASSING = {"OK", "NON-STRICT", "INFORMATIONAL", "UNIMPLEMENTED"}

report = json.load(open(sys.argv[1]))
exit_code = 0
for agent, cases in report.items():
    behaviour = Counter(c["behavior"] for c in cases.values())
    closing = Counter(c["behaviorClose"] for c in cases.values())
    failed = sorted(k for k, c in cases.items() if c["behavior"] not in PASSING)
    bad_close = sorted(k for k, c in cases.items() if c["behaviorClose"] not in PASSING)
    print(f"{agent}: {len(cases)} cases {dict(behaviour)} close={dict(closing)}")
    if failed:
        print(f"  FAILED: {failed}")
        exit_code = 1
    if bad_close:
        print(f"  BAD CLOSE: {bad_close}")
        exit_code = 1
    if len(cases) < 500:
        print(f"  ONLY {len(cases)} CASES RAN — the suite did not complete")
        exit_code = 1
sys.exit(exit_code)
