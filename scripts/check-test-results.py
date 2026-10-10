#!/usr/bin/env python3
"""Fail CI if a required Go test was excluded, skipped, or failed."""
import argparse
import json
from pathlib import Path


def check(events, required, package):
    if any(event.get("Action") == "fail" for event in events):
        raise ValueError("Go test log contains a failure")
    outcomes = {}
    for event in events:
        if event.get("Package") == package and event.get("Test") in required:
            action = event.get("Action")
            if action in {"pass", "skip", "fail"}:
                outcomes.setdefault(event["Test"], []).append(action)
    missing = sorted(name for name in required if outcomes.get(name) != ["pass"])
    if missing:
        raise ValueError("Required tests must each execute and pass once: " + ", ".join(missing))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("tests", nargs="+")
    parser.add_argument("--package", default="github.com/DoraFactory/doravota/app")
    args = parser.parse_args()
    try:
        events = [json.loads(line) for line in args.results.read_text().splitlines() if line.strip()]
        check(events, set(args.tests), args.package)
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + "\n")
    print("Required tests passed: " + ", ".join(args.tests))


if __name__ == "__main__":
    main()
