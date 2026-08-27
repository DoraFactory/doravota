#!/usr/bin/env python3
"""Plan and materialize paced mixed-load and adversarial transaction streams."""

import argparse
import json
import math
from pathlib import Path


VALID_MODES = ("classic", "hybrid", "native")
ATTACK_MODES = ("invalid-pqc", "oversized", "noncanonical", "bad-sequence")


def parse_weights(value, modes):
    parts = [int(item) for item in value.split(",")]
    if len(parts) != len(modes) or any(item < 0 for item in parts) or sum(parts) <= 0:
        raise argparse.ArgumentTypeError(
            f"expected {len(modes)} non-negative comma-separated weights"
        )
    return dict(zip(modes, parts))


def allocate(total, weights):
    weight_total = sum(weights.values())
    exact = {mode: total * weight / weight_total for mode, weight in weights.items()}
    counts = {mode: int(value) for mode, value in exact.items()}
    missing = total - sum(counts.values())
    order = sorted(weights, key=lambda mode: (exact[mode] - counts[mode], mode), reverse=True)
    for mode in order[:missing]:
        counts[mode] += 1
    return counts


def valid_phase(name, target_percent, duration, block_interval, block_max_gas, weights, gas):
    weighted_gas = sum(weights[mode] * gas[mode] for mode in VALID_MODES) / sum(weights.values())
    transactions_per_block = max(1, int(block_max_gas * target_percent / 100 / weighted_gas))
    blocks = max(1, math.ceil(duration / block_interval))
    total = transactions_per_block * blocks
    return {
        "name": name,
        "target_block_gas_percent": target_percent,
        "duration_seconds": duration,
        "planned_blocks": blocks,
        "transactions_per_block": transactions_per_block,
        "rate_per_second": total / duration,
        "total_transactions": total,
        "counts": allocate(total, weights),
    }


def write_interleaved(output_path, counts, handles):
    remaining = dict(counts)
    total = sum(remaining.values())
    if total == 0:
        output_path.write_text("", encoding="utf-8")
        return
    weights = {mode: count / total for mode, count in counts.items()}
    credit = {mode: 0.0 for mode in counts}
    with output_path.open("x", encoding="utf-8") as output:
        for _ in range(total):
            for mode in counts:
                if remaining[mode] > 0:
                    credit[mode] += weights[mode]
            available = [mode for mode in counts if remaining[mode] > 0]
            chosen = max(available, key=lambda mode: (credit[mode], mode))
            line = handles[chosen].readline()
            if not line:
                raise SystemExit(f"fixture {chosen} ended before the planned count")
            output.write(line)
            credit[chosen] -= 1.0
            remaining[chosen] -= 1


def create_plan(args):
    valid_weights = parse_weights(args.valid_weights, VALID_MODES)
    attack_weights = parse_weights(args.attack_weights, ATTACK_MODES)
    gas = {"classic": args.classic_gas, "hybrid": args.hybrid_gas, "native": args.native_gas}
    phases = [
        valid_phase(
            f"steady-{target}", target, args.steady_duration, args.block_interval,
            args.block_max_gas, valid_weights, gas,
        )
        for target in args.targets
    ]
    adversarial_valid = valid_phase(
        f"adversarial-valid-{args.adversarial_valid_target}",
        args.adversarial_valid_target,
        args.adversarial_duration,
        args.block_interval,
        args.block_max_gas,
        valid_weights,
        gas,
    )
    phases.append(adversarial_valid)
    attack_total = math.ceil(args.attack_rate * args.adversarial_duration)
    adversarial = {
        "name": "adversarial-rejected",
        "duration_seconds": args.adversarial_duration,
        "rate_per_second": args.attack_rate,
        "total_transactions": attack_total,
        "counts": allocate(attack_total, attack_weights),
        "concurrent_valid_phase": adversarial_valid["name"],
    }
    total_counts = {mode: 0 for mode in VALID_MODES + ATTACK_MODES}
    for phase in phases:
        for mode, count in phase["counts"].items():
            total_counts[mode] += count
    for mode, count in adversarial["counts"].items():
        total_counts[mode] += count
    return {
        "block_max_gas": args.block_max_gas,
        "block_interval_seconds": args.block_interval,
        "valid_weights": valid_weights,
        "attack_weights": attack_weights,
        "gas_limits": gas,
        "valid_phases": phases,
        "adversarial_phase": adversarial,
        "total_counts": total_counts,
    }


def materialize(plan, fixture_dir, output_dir):
    output_dir.mkdir(parents=True, exist_ok=False)
    valid_handles = {
        mode: (fixture_dir / f"{mode}.txs.jsonl").open("r", encoding="utf-8")
        for mode in VALID_MODES
    }
    try:
        for phase in plan["valid_phases"]:
            write_interleaved(output_dir / f"{phase['name']}.txs.jsonl", phase["counts"], valid_handles)
    finally:
        for handle in valid_handles.values():
            handle.close()

    attack_handles = {
        mode: (fixture_dir / f"{mode}.txs.jsonl").open("r", encoding="utf-8")
        for mode in ATTACK_MODES
    }
    try:
        phase = plan["adversarial_phase"]
        write_interleaved(output_dir / f"{phase['name']}.txs.jsonl", phase["counts"], attack_handles)
    finally:
        for handle in attack_handles.values():
            handle.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan-out")
    parser.add_argument("--materialize", action="store_true")
    parser.add_argument("--plan")
    parser.add_argument("--fixtures")
    parser.add_argument("--output")
    parser.add_argument("--targets", default="30,60,90")
    parser.add_argument("--steady-duration", type=int, default=300)
    parser.add_argument("--adversarial-duration", type=int, default=300)
    parser.add_argument("--adversarial-valid-target", type=int, default=60)
    parser.add_argument("--attack-rate", type=float, default=300.0)
    parser.add_argument("--valid-weights", default="40,30,30")
    parser.add_argument("--attack-weights", default="85,1,4,10")
    parser.add_argument("--block-max-gas", type=int, default=100_000_000)
    parser.add_argument("--block-interval", type=float, default=2.0)
    parser.add_argument("--classic-gas", type=int, default=120_000)
    parser.add_argument("--hybrid-gas", type=int, default=400_000)
    parser.add_argument("--native-gas", type=int, default=320_000)
    args = parser.parse_args()

    if args.materialize:
        if not args.plan or not args.fixtures or not args.output:
            parser.error("--materialize requires --plan, --fixtures, and --output")
        with open(args.plan, encoding="utf-8") as source:
            plan = json.load(source)
        materialize(plan, Path(args.fixtures), Path(args.output))
        return

    args.targets = [int(value) for value in args.targets.split(",")]
    if (
        not args.plan_out
        or any(target <= 0 or target > 100 for target in args.targets)
        or args.steady_duration <= 0
        or args.adversarial_duration <= 0
        or args.attack_rate <= 0
        or args.block_interval <= 0
    ):
        parser.error("invalid planning arguments")
    plan = create_plan(args)
    with open(args.plan_out, "x", encoding="utf-8") as output:
        json.dump(plan, output, indent=2)
        output.write("\n")
    print(json.dumps(plan, indent=2))


if __name__ == "__main__":
    main()
