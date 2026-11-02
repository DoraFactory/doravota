#!/usr/bin/env bash
set -euo pipefail
for kind in classic hybrid native; do
  echo "START ALL-POOLS $kind"
  docker run --name "pqcauth-91-gate-$kind" --network none --cpus 3 --memory 7g --memory-swap 7g --pids-limit 256 \
    -e GOMAXPROCS=2 -e PYTHONDONTWRITEBYTECODE=1 \
    -v /tmp/pqcauth-allpools91c.GJtlhg:/work \
    -v /tmp/pqcauth-acceptance91.nGLhyw/src/release/dorad-v1.1.0-dev-linux-amd64:/binaries/dorad:ro \
    -v /tmp/pqcauth-acceptance91.nGLhyw/app.test:/binaries/fixture:ro \
    -w /work/harness golang:1.26.5-bookworm \
    python3 rehearse-pqcauth-capacity.py --binary /binaries/dorad --fixture-binary /binaries/fixture \
      --work-dir "/work/$kind" --kind "$kind" --count 5000 --baseline-blocks 30 --all-validator-pools \
    > "/tmp/pqcauth-allpools91c.GJtlhg/$kind.log" 2>&1
  jq '{kind,functional_pass,committed,loaded_interval_count,baseline_p95_seconds,loaded_p95_seconds,p95_within_15_percent_baseline}' "/tmp/pqcauth-allpools91c.GJtlhg/$kind/evidence/result.json"
done
