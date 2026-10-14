# Zero-Data Intent Governance Gateway (v3.0)

[![Tests](https://github.com/abood879/zero-data-intent-gateway/actions/workflows/tests.yml/badge.svg)](https://github.com/abood879/zero-data-intent-gateway/actions)
[![Release](https://img.shields.io/github/v/release/abood879/zero-data-intent-gateway?color=blue)](https://github.com/abood879/zero-data-intent-gateway/releases/latest)
[![Tests Passing](https://img.shields.io/badge/tests-18%2F18%20passed-brightgreen)](https://github.com/abood879/zero-data-intent-gateway)

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?style=flat&logo=FastAPI&logoColor=white)](https://fastapi.tiangolo.com)
[![Python 3.11](https://img.shields.io/badge/Python-3.11+-3776AB.svg?style=flat&logo=Python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?style=flat&logo=docker&logoColor=white)](https://docker.com)
[![Enterprise CI Pipeline](https://github.com/abood879/zero-data-intent-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/abood879/zero-data-intent-gateway/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A sub-millisecond line-rate governance middleware designed to enforce deterministic state boundaries over autonomous enterprise AI agents. Eliminates statistical drift, unauthorized tool invocation, and token consumption via mathematically bounded State Collapse.

## 🧪 Instant Reproduction (One-Line Verification)

```bash
# Run full adversarial and fail-fast test suite locally
pytest tests/ -v
```

---

## Architectural Philosophy: Deterministic State Collapse (DoF)

Traditional AI guardrails rely on secondary probabilistic models (LLM-as-a-Judge), compounding latency, operational cost, and nondeterministic failure vectors. The **Zero-Data Intent Architecture** evaluates mission-critical enterprise transactions through dynamic **Degrees of Freedom (DoF)**:

$$DoF = N_{\text{violations}} + N_{\text{missing parameters}}$$

### The 3 Operational Tiers

| Tier | State | Mathematical Condition | Behavior | Latency / Tokens |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1** | **Intent Lock** | $DoF = 0$ | Bypasses downstream LLM inference entirely. Executes pre-cleared operations instantly with deterministic state resolution. | **<0.05 ms** / **0 Tokens** |
| **Tier 2** | **Active Disambiguation** | $DoF = 1$ | Intercepts isolated parameter ambiguity (e.g., missing sign-off). Dispatches a targeted probe back to the caller to collapse state to $DoF = 0$ without triggering approval fatigue. | **<0.05 ms** / **0 Tokens** |
| **Tier 3** | **Deterministic Halt** | $DoF > 1$ | Hard stop on multi-vector policy violations or unauthorized vendors. Records forensic cryptographic state and halts execution. | **<0.05 ms** / **0 Tokens** |

## Empirical Micro-Benchmarks

Reference measurements for the deterministic Tier 1 engine evaluation:

| Metric | Latency |
| :--- | :--- |
| Median (p50) | 9.307 µs (0.0093 ms) |
| Mean | 10.005 µs (0.0100 ms) |
| 95th percentile (p95) | 11.897 µs (0.0118 ms) |
| 99th percentile (p99) | 17.112 µs (0.0171 ms) |

Run the benchmark from the repository root with:

```bash
python -m benchmarks.benchmark
```

The benchmark measures 1,000 Tier 1 evaluations with audit appends stubbed. Results vary with the execution environment.

---

## Core Security & Enterprise Architecture

* **Strict Constrained Schemas**: Enforces `ConfigDict(strict=True, extra="forbid")` via Pydantic to neutralize prompt injections and structural bypass attempts at wire speed.
* **Distributed Atomic Ledger**: Built with Redis append-only streams and atomic Lua scripts to prevent race conditions across multi-worker clusters. Gracefully falls back to local in-memory hashing for isolated nodes.
* **Policy-as-Code via OPA**: Integrates with Open Policy Agent (OPA Sidecar) running custom declarative Rego policies (`config/policy.rego`).
* **Cryptographic Audit Ledger**: Each transaction decision is anchored in an immutable SHA-256 hash chain:
  $$\text{Audit Hash}_{i} = \text{SHA256}(\text{Audit Hash}_{i-1} \parallel \text{Payload} \parallel \text{Decision} \parallel \text{Timestamp})$$
* **Enterprise Observability**: Real-time Prometheus metrics exporter (`/metrics`) exposing latency histograms and decision counters.
* **Automated CI/CD Pipeline**: GitHub Actions test automation running complete functional suites and Docker container builds on every commit.
* **Agentic Python SDK**: Direct wrapper (`sdk.py`) providing drop-in integration with LangChain, CrewAI, AutoGen, or custom autonomous pipelines.

---

## System Topology

```text
[ Autonomous AI Agent ]
         │
         ▼ (HTTP POST / Payload)
┌────────────────────────────────────────────────────────┐
│  Zero-Data Intent Governance Gateway (:8080)           │
│  ├─ Strict Schema Validator (Pydantic / Strict Type)   │
│  ├─ Deterministic State Engine (DoF Calculation)       │
│  └─ Prometheus Exporter (/metrics)                     │
└────────┬──────────────────────────────────────┬────────┘
         │ (Sidecar Evaluation)                 │ (Audit Append)
         ▼                                      ▼
┌──────────────────┐                  ┌──────────────────┐
│ OPA Engine (:8181│                  │ Redis Ledger     │
│ (Rego Policies)  │                  │ (:6379 / Atomic) │
└──────────────────┘                  └──────────────────┘