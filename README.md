# Zero-Data Intent Governance Gateway (v3.0)

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?style=flat&logo=FastAPI&logoColor=white)](https://fastapi.tiangolo.com)
[![Python 3.11](https://img.shields.io/badge/Python-3.11+-3776AB.svg?style=flat&logo=Python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?style=flat&logo=docker&logoColor=white)](https://docker.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A sub-millisecond line-rate governance middleware designed to enforce deterministic state boundaries over autonomous enterprise AI agents. Eliminates statistical drift, unauthorized tool invocation, and token consumption via mathematically bounded State Collapse.

---

## Architectural Philosophy: Deterministic State Collapse (DoF)

Traditional AI guardrails rely on secondary probabilistic models (LLM-as-a-Judge), compounding latency and failure vectors. The **Zero-Data Intent Architecture** evaluates mission-critical enterprise transactions through dynamic **Degrees of Freedom (DoF)**:

$$DoF = N_{\text{violations}} + N_{\text{missing\_parameters}}$$

### The 3 Operational Tiers

| Tier | State | Mathematical Condition | Behavior | Latency / Tokens |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1** | **Intent Lock** | $DoF = 0$ | Bypasses downstream LLM inference entirely. Executes pre-cleared operations instantly with deterministic state resolution. | **<0.05 ms** / **0 Tokens** |
| **Tier 2** | **Active Disambiguation** | $DoF = 1$ | Intercepts isolated parameter ambiguity (e.g., missing sign-off). Dispatches a targeted probe back to the caller to collapse state to $DoF = 0$ without triggering approval fatigue. | **<0.05 ms** / **0 Tokens** |
| **Tier 3** | **Deterministic Halt** | $DoF > 1$ | Hard stop on multi-vector policy violations or unauthorized vendors. Records forensic cryptographic state and halts execution. | **<0.05 ms** / **0 Tokens** |

---

## Core Security Features

- **Strict Constrained Schemas**: Enforces `ConfigDict(strict=True, extra="forbid")` via Pydantic to neutralize prompt injections and structural bypass attempts at wire speed.
- **Cryptographic Audit Ledger**: Each transaction decision is anchored in an immutable SHA-256 hash chain:
  $$\text{Audit\_Hash}_{i} = \text{SHA256}(\text{Audit\_Hash}_{i-1} \parallel \text{Payload} \parallel \text{Decision} \parallel \text{Timestamp})$$
- **Agentic Python SDK**: Direct wrapper (`sdk.py`) providing drop-in integration with LangChain, CrewAI, AutoGen, or custom autonomous pipelines.

---

## Quickstart (Local Deployment)

### 1. Using Docker (Recommended)

```bash
docker build -t zero-data-intent-gateway .
docker run -p 8080:8080 zero-data-intent-gateway
