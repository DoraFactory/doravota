#!/usr/bin/env python3
"""Remote-only four-validator v1.0.0 -> v1.0.1 -> v1.1.0 rehearsal.

Run in a resource-bounded container with --network none. OLD_DORAD and NEW_DORAD
are the released v1.0.0 and v1.0.1 binaries; PQC_DORAD is the candidate. All keys
are synthetic. REHEARSAL_DIR must not exist. No public network is contacted.
"""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess

pqc = Path(os.environ["PQC_DORAD"]).resolve(strict=True)
v101 = Path(os.environ["NEW_DORAD"]).resolve(strict=True)
assert hashlib.sha256(v101.read_bytes()).hexdigest() == "04bd2d0dced7ccf1f993a70fb2be6b1718e0f1852c27f1bdeef0fa49eaea1696"

# Reuse the unchanged released-IBC rehearsal, including its early-start guard,
# four-validator AppHash comparison and restart without upgrade-info.json.
s = runpy.run_path(str(Path(__file__).with_name("rehearse-amino-upgrade.py")))
root, homes, result = s["ROOT"], s["homes"], s["result"]
(root / "v101-result.json").write_text(json.dumps(result, indent=2))
result.pop("status", None)
result["pqc_sha256"] = hashlib.sha256(pqc.read_bytes()).hexdigest()
result["scope"] = "isolated sequential governance upgrades; not a mainnet snapshot or public IBC test"
start, stop, wait, tx, cli = (s[x] for x in ("start", "stop", "wait", "tx", "cli"))
query, synced = s["query"], s["synced"]
old = s["NEW"]
rpc = f"http://127.0.0.1:{s['rpcs'][0]}"
try:
    start(old, "v101-before-pqc")
    prior = max(int(x["latest_block_height"]) for x in result["after_restart"])
    wait(lambda: synced(prior + 3))
    height = int(query(0, "status")["sync_info"]["latest_block_height"]) + 100
    proposal = json.loads((root / "proposal.json").read_text())
    proposal["messages"][0]["plan"].update(name="v1.1.0", height=str(height))
    proposal["title"] = "Isolated PQCAuth upgrade after v1.0.1"
    path = root / "pqcauth-proposal.json"
    path.write_text(json.dumps(proposal, indent=2))
    result["pqc_proposal_tx"] = tx(old, 0, "gov", "submit-proposal", path)
    result["pqc_vote_txs"] = [tx(old, i, "gov", "vote", "2", "yes") for i in range(4)]
    def passed():
        p = json.loads(cli(old, 0, "query", "gov", "proposal", "2", "--node", rpc, "--output", "json"))
        return p if p["proposal"]["status"] == "PROPOSAL_STATUS_PASSED" else None
    result["pqc_proposal"] = wait(passed)
    stop()
    early = subprocess.run(s["command"](pqc, 0), text=True, capture_output=True, timeout=15)
    (root / "pqc-early-start.log").write_text(early.stdout + early.stderr)
    assert early.returncode != 0, "PQC candidate must not run before its scheduled activation"
    result["pqc_premature_start_rejected"] = True
    start(old, "v101-resumed-for-pqc")
    def halted():
        for home in homes:
            p = home / "data/upgrade-info.json"
            if not p.exists():
                return False
            info = json.loads(p.read_text())
            if info["name"] != "v1.1.0" or int(info["height"]) != height:
                return False
        return True
    wait(halted, seconds=120)
    stop()
    start(pqc, "pqc-upgraded")
    result["pqc_after_upgrade"] = wait(lambda: synced(height + 4))
    result["pqc_after_transfer"] = tx(pqc, 0, "bank", "send", s["addresses"][0], s["addresses"][1], "11peaka")
    params = json.loads(cli(pqc, 0, "query", "pqcauth", "params", "--node", rpc, "--output", "json"))
    result["pqc_params"] = params
    assert params["params"]["enforcement_mode"] in ("ENFORCEMENT_MODE_OPTIONAL", "OPTIONAL", 2), params
    def matching(label, h):
        hashes = [query(i, f"commit?height={h}")["signed_header"]["header"]["app_hash"] for i in range(4)]
        assert len(set(hashes)) == 1, hashes
        result[label] = {"height": h, "hash": hashes[0], "nodes": 4}
    matching("pqc_matching_app_hash", height + 2)
    prior = max(int(x["latest_block_height"]) for x in synced(height + 4))
    stop()
    for home in homes:
        (home / "data/upgrade-info.json").rename(home / "data/rehearsal-pqc-completed.json")
    start(pqc, "pqc-restarted")
    result["pqc_after_restart"] = wait(lambda: synced(prior + 4))
    result["pqc_restart_transfer"] = tx(pqc, 0, "bank", "send", s["addresses"][0], s["addresses"][1], "13peaka")
    matching("pqc_restart_matching_app_hash", prior + 2)
    result["pqc_upgrade_height"] = height
    result["status"] = "PASS"
    print(json.dumps(result, indent=2), flush=True)
finally:
    stop()
    (root / "result.json").write_text(json.dumps(result, indent=2))
