import os
import sys
import time
from math import ceil
from pathlib import Path
from unittest.mock import patch

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.engine import evaluate_governance, ledger


ITERATIONS = 1_000
ROOT = Path(__file__).resolve().parents[1]


def percentile(values: list[int], percentile_value: int) -> int:
    ordered = sorted(values)
    index = ceil(percentile_value * len(ordered) / 100) - 1
    return ordered[index]


def main() -> None:
    with (ROOT / "config" / "policies.yaml").open(encoding="utf-8") as policy_file:
        policies = yaml.safe_load(policy_file)

    payload = {
        "id": "TX-BENCHMARK",
        "amount": 1200.0,
        "vendor": "AWS_Cloud_Global",
        "department": "Engineering",
        "budget_cleared": True,
    }
    latencies_ns = []

    # Keep this suite focused on the deterministic local policy engine.
    os.environ.pop("OPA_URL", None)

    with patch.object(ledger, "append_record", return_value="BENCHMARK"):
        for _ in range(ITERATIONS):
            start_ns = time.perf_counter_ns()
            result = evaluate_governance(payload, policies)
            elapsed_ns = time.perf_counter_ns() - start_ns

            assert result["status"] == "INTENT_LOCKED", result
            assert result["degrees_of_freedom"] == 0, result
            latencies_ns.append(elapsed_ns)

    statistics = {
        "Min Latency": min(latencies_ns),
        "Mean Latency": round(sum(latencies_ns) / len(latencies_ns)),
        "p50 / Median": percentile(latencies_ns, 50),
        "p95": percentile(latencies_ns, 95),
        "p99": percentile(latencies_ns, 99),
    }

    print(f"Zero-Data Intent Gateway benchmark ({ITERATIONS} Tier 1 iterations)")
    print("Measured latency: deterministic engine evaluation, audit append stubbed")
    for name, latency_ns in statistics.items():
        print(f"{name}: {latency_ns / 1_000:.3f} µs ({latency_ns / 1_000_000:.6f} ms)")
    print("Validation: status=INTENT_LOCKED, DoF=0")


if __name__ == "__main__":
    main()