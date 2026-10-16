"""Measure Redis async lock acquisition latency under concurrent load."""

import asyncio
import os
import statistics
import time
import uuid

import redis.asyncio as redis_async


ITERATIONS = 1_000
LOCK_TIMEOUT_SECONDS = 30


async def _measure_acquisition(
    client: redis_async.Redis,
    benchmark_id: str,
    iteration: int,
) -> float:
    lock = client.lock(
        f"benchmark:{benchmark_id}:{iteration}",
        timeout=LOCK_TIMEOUT_SECONDS,
        blocking_timeout=10,
    )
    started_at = time.perf_counter()
    acquired = await lock.acquire()
    latency_seconds = time.perf_counter() - started_at
    if not acquired:
        raise TimeoutError(f"Redis lock {iteration} could not be acquired.")
    await lock.release()
    return latency_seconds


async def main() -> None:
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    client = redis_async.from_url(
        redis_url,
        decode_responses=True,
        max_connections=ITERATIONS,
        socket_connect_timeout=10,
        socket_timeout=10,
    )
    benchmark_id = uuid.uuid4().hex
    try:
        await client.ping()
        await asyncio.gather(*(client.ping() for _ in range(ITERATIONS)))
        latencies = await asyncio.gather(
            *(
                _measure_acquisition(client, benchmark_id, iteration)
                for iteration in range(ITERATIONS)
            )
        )
    finally:
        await client.aclose()

    average_ms = statistics.fmean(latencies) * 1_000
    p95_ms = sorted(latencies)[int(ITERATIONS * 0.95) - 1] * 1_000
    print(f"Redis async lock acquisition benchmark ({ITERATIONS} concurrent locks)")
    print(f"Average acquisition latency: {average_ms:.3f} ms")
    print(f"p95 acquisition latency: {p95_ms:.3f} ms")
    print(
        "Scope: lock acquire round-trip latency after warming the connection pool; "
        "results depend on host, network, and Redis load and are not a production SLA."
    )


if __name__ == "__main__":
    asyncio.run(main())
