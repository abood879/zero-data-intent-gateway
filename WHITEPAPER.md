# Zero-Data Intent Gateway: Enterprise Security Whitepaper

## Executive Summary

The Zero-Data Intent Gateway is a policy-enforcement and transaction-control
layer for autonomous agents that initiate high-impact actions. It is designed
to ensure an agent's intent is authorized before a provider operation is
dispatched, while maintaining durable budget reservations, idempotency state,
and a tamper-evident local audit trail.

The repository implements a Python gateway and SDK, SQLite-backed financial
state, Redis-backed distributed coordination for proxy idempotency locks, and
a local mock provider for integration exercises. The broader enterprise
architecture described here is a target design: components such as a
multi-host egress proxy, PostgreSQL-backed distributed state, and external
immutable audit anchoring are not represented as deployed capabilities unless
explicitly stated.

## Security Objectives

The gateway is designed around the following objectives:

1. **Authorize before dispatch.** Evaluate a request against server-controlled
   policy before making an external provider call.
2. **Fail closed.** Reject malformed, unauthorized, over-limit, or
   unresolvable requests rather than treating an error as approval.
3. **Control cumulative exposure.** Reserve funds atomically before dispatch
   and retain reservations when provider outcomes are uncertain.
4. **Make retries safe.** Bind idempotency keys to request identity and
   canonical payload data, returning cached confirmations for committed
   duplicates.
5. **Support forensic review.** Record policy decisions and execution
   outcomes in an integrity-checked audit chain.
6. **Limit agent network access.** In the Compose deployment, isolate the
   agent from the provider and require provider traffic to pass through the
   gateway.

## Reference Deployment

The local Compose topology uses separate internal and external networks:

```text
AI agent
   │ internal-only-net
   ▼
Intent gateway ───────── external-net ───────── Mock provider
   │
   └── internal-only-net ── Redis
```

The gateway connects to both networks. The agent connects only to
`internal-only-net`, while the mock provider connects only to `external-net`.
The gateway's `/v1/proxy/transfers` API is an application-level reverse proxy;
it is not a general-purpose HTTP `CONNECT` proxy. Compose health checks gate
gateway startup on Redis readiness and agent startup on gateway health.

This local topology is an integration and development deployment. Production
network policy should independently enforce that agent workloads cannot route
directly to provider endpoints, including through alternate interfaces,
sidecars, host networking, or permissive egress rules.

## Request Authorization and Policy

The gateway authenticates callers using bearer tokens mapped to server-side
roles and user identities. It does not trust a caller-supplied role or budget
limit. For transfer requests, it:

1. Validates the request body and requires the `Idempotency-Key` header to
   match the key in the payload.
2. Evaluates the transfer using the unified governance engine and
   server-controlled transaction limits.
3. Rejects policy violations before contacting the provider.
4. Acquires a Redis lock for the idempotency key when Redis is configured.
5. Atomically reserves cumulative budget and checks durable idempotency state.
6. Forwards an authorized request to the provider and records its outcome.

Transaction limits, cumulative role budgets, and tool permissions are loaded
from `config/policies.yaml`. An authenticated `admin` or
`governance_admin` can request an in-process reload through
`POST /v1/admin/reload-policies`. New policy values are validated before the
active in-memory policy maps are replaced. Environment overrides for
currency-specific critical limits and role budgets take precedence over the
file.

## Budget Reservations and Idempotency

SQLite transactions using `BEGIN IMMEDIATE` provide durable, atomic budget
reservations and idempotency state transitions in the current implementation.
The Redis lock serializes concurrent requests with the same idempotency key
across gateway instances when Redis is configured; it does not replace the
durable database transaction. Redis lock acquisition failures fail closed.

An idempotency key is bound to the authenticated identity and canonical
transaction payload. A committed duplicate receives a cached confirmation
without a second provider dispatch. Reuse of a key with a different payload
is rejected. Reservations are committed after a successful provider response.
Definitive pre-dispatch or provider rejections can be released according to
their state; ambiguous outcomes remain held for reconciliation rather than
being treated as safe to retry.

SQLite remains a local durable store and a possible write-contention
bottleneck. The current implementation does not establish multi-host database
consistency or a production throughput limit. A production deployment should
select a shared transactional state engine based on its consistency,
availability, durability, and recovery requirements.

## Auditability and Recovery

The SDK's local JSONL audit ledger records policy evaluation and execution
outcomes in a SHA-256 hash chain. It verifies the chain at startup and uses
filesystem locking and flush/sync behavior to serialize local writers. Audit
events include bounded, sanitized exception summaries rather than stack
traces.

The local ledger is not an independently immutable or externally anchored
audit service. Production environments requiring stronger evidence retention
should export events through a durable outbox to a separately administered
append-only or write-once store, and regularly verify external checkpoints.

The gateway treats failures after provider dispatch may have started as
potentially uncertain. Such reservations should be reconciled against the
provider using its idempotency and transaction-status facilities before
release or retry. A local intent record alone cannot prove whether a remote
provider completed an operation.

## Performance and Validation

The repository includes focused tests for policy rejection, budget
reservations, duplicate suppression, and proxy behavior. It also includes a
local deterministic policy-evaluation microbenchmark and a Redis lock
acquisition benchmark. These benchmarks measure different, limited scopes;
neither is an end-to-end latency guarantee.

Redis lock latency depends on deployment topology, network distance,
concurrency, Redis persistence settings, and workload. The benchmark reports
measured acquisition latency for its configured Redis instance; results must
be collected in the target production environment using representative load
before making sub-millisecond performance claims. The current gateway's
SQLite transactions, HTTP handling, audit persistence, and provider latency
are not included in a Redis-lock-only measurement.

## Deployment Considerations

- Keep bearer tokens and other secrets in a protected deployment secret
  manager; do not commit real credentials.
- Restrict gateway access to trusted agent workloads and protect administrative
  policy reload access with dedicated identities and network controls.
- Mount policy configuration read-only and update it atomically before
  requesting a reload.
- Keep SQLite files on storage with appropriate local locking and durability
  semantics; do not use SQLite on a cross-host network filesystem.
- Monitor Redis and gateway health, lock failures, provider error rates,
  unresolved reservations, and reconciliation backlog.
- Exercise provider timeouts, retries, process restarts, database contention,
  and Redis outages in deployment-specific failure tests.

## Limitations and Roadmap

The current repository is an evolving implementation and local reference
deployment, not a complete enterprise production control plane. Before
production use, the deployment should validate network-enforced egress
boundaries, shared durable state across gateway instances, external audit
retention, operational reconciliation workflows, and measured performance
under realistic concurrent load. Architecture goals and local test results
should not be interpreted as certifications, production guarantees, or
independent audit findings.
