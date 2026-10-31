#!/usr/bin/env python3
"""Candidate-build policy only; the public release workflow stays stable-only."""
import os


def allow_prerelease(event_name, ref_name, base_ref):
    # A PR builds its target branch's candidate, regardless of the topic/fork
    # branch's name. In particular, a PQC branch PR into main is NOT exempt.
    if event_name == "pull_request":
        branch = base_ref
    elif event_name in ("push", "workflow_dispatch"):
        branch = ref_name
    else:
        return False
    return branch == "feature/pqcauth-sdk-keyring"


if __name__ == "__main__":
    print("true" if allow_prerelease(
        os.environ.get("GITHUB_EVENT_NAME", ""),
        os.environ.get("GITHUB_REF_NAME", ""),
        os.environ.get("GITHUB_BASE_REF", ""),
    ) else "false")
