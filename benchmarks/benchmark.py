import sys
import time
from math import ceil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.engine import governance_engine


ITERATIONS = 1_000


def percentile(values: list[int], percentile_value: int) -> int:
    ordered = sorted(values)
    index = ceil(percentile_value * len(ordered) / 100) - 1
    return ordered[index]


def main() -> None:
    payload = {
        "tool": "wire_transfer",
        "parameters": {"amount": 1200.0, "currency": "USD"},
        "context": {"role": "finance_operator", "user_id": "benchmark"},
    }
    latencies_ns = []

    for _ in range(ITERATIONS):
        start_ns = time.perf_counter_ns()
        degrees_of_freedom, violations, _ = governance_engine.evaluate(payload)
        elapsed_ns = time.perf_counter_ns() - start_ns

        assert degrees_of_freedom == 0, violations
        latencies_ns.append(elapsed_ns)

    statistics = {
        "Min Latency": min(latencies_ns),
        "Mean Latency": round(sum(latencies_ns) / len(latencies_ns)),
        "p50 / Median": percentile(latencies_ns, 50),
        "p95": percentile(latencies_ns, 95),
        "p99": percentile(latencies_ns, 99),
    }

    print(f"Local policy-evaluation microbenchmark ({ITERATIONS} Tier 1 iterations)")
    print(
        "Scope: deterministic policy evaluation only; no audit append is performed. "
        "Excludes SQLite reservations, HTTP, concurrency, and provider/network latency."
    )
    for name, latency_ns in statistics.items():
        print(f"{name}: {latency_ns / 1_000:.3f} µs ({latency_ns / 1_000_000:.6f} ms)")
    print("Validation: DoF=0")


if __name__ == "__main__":
    main()