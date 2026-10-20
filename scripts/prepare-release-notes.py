#!/usr/bin/env python3
"""Validate the public release tag and extract its exact changelog section."""
import argparse
import re
from pathlib import Path


def validate_tag(tag, expected, allow_prerelease=False):
    pattern = r"v[0-9]+\.[0-9]+\.[0-9]+"
    if allow_prerelease:
        pattern += r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
    if not re.fullmatch(pattern, tag) or tag != expected:
        raise ValueError(f"Release tag must match VERSION exactly: {expected}")


def extract_notes(changelog, tag):
    lines = changelog.splitlines()
    heading = f"## [{tag}]"
    if lines.count(heading) != 1:
        raise ValueError(f"Expected exactly one changelog heading: {heading}")
    section = []
    for line in lines[lines.index(heading) + 1:]:
        if line.startswith("## "):
            break
        section.append(line)
    notes = "\n".join(section).strip()
    if not notes:
        raise ValueError("Release notes are empty")
    return notes + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--allow-prerelease", action="store_true", help="Candidate CI only; public releases remain stable-tag-only")
    parser.add_argument("--output", type=Path, default=Path("release_notes.md"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        validate_tag(args.tag, (root / "VERSION").read_text().strip(), args.allow_prerelease)
        notes = extract_notes((root / "CHANGELOG.md").read_text(), args.tag)
        supplement = root / "docs" / f"RELEASE-{args.tag}.md"
        if supplement.is_file():
            notes += "\n" + supplement.read_text()
        args.output.write_text(notes)
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + "\n")
    print(f"Prepared release notes for {args.tag}")


if __name__ == "__main__":
    main()
