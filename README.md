# Zero-Data Intent Gateway

> "We don't just tell AI agents what they shouldn't do. We control what they can execute."

**A fail-closed policy enforcement and transaction-control plane for autonomous AI agents: deterministic authorization, durable execution state, provider-level idempotency, and cryptographic forensic recovery for high-impact financial actions.**

## Architecture & Design Principles: Enterprise Blueprint v2

Enterprise Blueprint v2 is the target production architecture. The repository currently contains a Python gateway and SDK with SQLite-backed budget reservations and a local hash-chained audit ledger; the distributed proxy and state-engine components below describe the planned production evolution, not features already deployed by this repository.

### Out-of-Process Egress Proxy

The production design places an independent egress gateway between agent workloads and external providers:

```text
┌────────────────────────┐       ┌─────────────────────────────┐       ┌──────────────────┐
│ AI agent runtime       │──────▶│ Egress gateway / sidecar    │──────▶│ External provider│
│ No provider credentials│       │ Policy, budget, idempotency │       │                  │
│ Direct egress blocked  │       │ Dispatch and reconciliation │       │                  │
└────────────────────────┘       └──────────────┬──────────────┘       └──────────────────┘
                                                 │
                                  ┌──────────────┴──────────────┐
                                  │ Durable state and audit     │
                                  └─────────────────────────────┘
```

- The AI agent runtime holds **zero external provider credentials**.
- Network policy blocks direct provider egress from agent workloads; provider traffic must traverse the gateway.
- The gateway is intended to be a separate process and network-enforced security boundary, not merely an SDK decorator.
- A durable dispatch-intent record and a provider-supported idempotency key provide the basis for crash recovery and reconciliation. An intent record alone cannot prove whether a remote provider completed an operation.

### Planned Distributed State Engine

The current implementation is a Python gateway using SQLite for budget reservations and local durable state. SQLite serializes writes, so contention can constrain throughput; this repository does not establish production latency or capacity limits. Enterprise Blueprint v2 envisions moving the shared, distributed control plane to PostgreSQL and/or Redis, selected according to each operation's consistency and durability requirements.

- PostgreSQL is a candidate for transactional budget, idempotency, and outbox state across gateway instances.
- Redis with carefully scoped atomic scripts is a candidate for latency-sensitive coordination where its persistence and recovery guarantees meet the deployment requirements.
- Audit events are intended to flow through an outbox to Kafka or Redpanda, with asynchronous external/WORM anchoring.
- Sub-millisecond distributed operation is an unvalidated design objective, not a measured result or performance guarantee. The current benchmark measures only deterministic local policy evaluation and performs no audit append; it excludes SQLite reservations, audit persistence, HTTP, concurrency, and provider/network latency.

### Deterministic Idempotency Lifecycle

Each idempotency key is bound to a canonical payload hash and the relevant transaction identity. The durable lifecycle is:

| State | Meaning | Retry behavior |
| --- | --- | --- |
| `PENDING` | Reservation or execution is active; outcome is not yet final. | Reject duplicate in-flight requests; reconcile uncertain outcomes. |
| `COMMITTED` | The operation has a confirmed successful outcome. | Return the cached confirmation for a matching payload. |
| `ABORTED` | The operation was confirmed to have aborted before dispatch. | Allow a new reservation for the same key and matching payload. |

A mismatched payload hash is rejected as an idempotency conflict. The production design intends to derive stable keys from a canonical payload hash plus stable agent and workflow identifiers, so retries can retain their identity across process restarts. Provider-level idempotency and reconciliation remain essential: local state cannot by itself guarantee exactly-once effects at a remote provider.

## Red-Team Audit Status

The project has undergone a rigorous architectural Red-Team review focused on the boundary between an in-process SDK and a distributed financial gateway. The review highlighted the need for network-enforced egress control, durable state shared across workers, deterministic retry identity, and explicit handling of uncertain provider outcomes.

- **Test result:** `python3 -m pytest tests/ -v` passed **63/63 tests** in the current full test suite, including adversarial coverage for in-flight network failures locking budgets for reconciliation, currency-isolated budget tracking, and rejection of payload tampering.
- **Lifecycle hardening:** Matching retries after a confirmed pre-dispatch abort are permitted; committed duplicates receive cached confirmations; post-dispatch exceptions remain unresolved for reconciliation.
- **Architecture assessment:** Enterprise Blueprint v2 received an **8.5/10** vision assessment as a production-grade paradigm for enterprise FinTech integration. This is an architectural assessment, not a certification or evidence that the target distributed components are already deployed.

## Current Repository Status

The codebase is an evolving implementation, not yet the complete Enterprise Blueprint v2 deployment:

- Python policy evaluation and protected-tool SDK in `app/engine.py` and `sdk.py`.
- SQLite-backed cumulative budget reservations and idempotency registry.
- Local JSONL audit ledger with a SHA-256 hash chain and sanitized exception summaries.
- Adversarial and API tests runnable with:

```bash
python3 -m pytest tests/ -v
```

`python3 benchmarks/benchmark.py` measures only local deterministic policy evaluation; it does not perform an audit append. Its results are not end-to-end gateway latency or a claim about performance under concurrent load.

The Compose deployment routes agent transfers through `POST /v1/proxy/transfers`; the gateway applies policy and budget checks before forwarding to the mock provider. Redis on the internal network supplies a distributed async lock per idempotency key; the durable SQLite transaction remains authoritative for budget and idempotency state. When `REDIS_URL` is configured, lock-service errors fail closed; without it, local development uses SQLite's transactional protection. Set `TOKEN_IDENTITY_MAP` to a JSON token-to-identity map and set `GATEWAY_API_TOKEN` to one of the tokens in that map before running `docker compose up --build`. The proxy is an API endpoint, not a general-purpose HTTP `CONNECT` proxy.

Gateway transaction limits, cumulative role budgets, and tool permissions are loaded from `config/policies.yaml`. The `POST /v1/admin/reload-policies` endpoint re-reads this mounted file without restarting Uvicorn and is restricted to identities with the `admin` or `governance_admin` role. Environment overrides such as `GATEWAY_CRITICAL_LIMIT_<CURRENCY>` and `GATEWAY_ROLE_BUDGET_LIMITS` take precedence over file values.

For the current security model, deployment limitations, and configuration details, see [SECURITY.md](SECURITY.md).
