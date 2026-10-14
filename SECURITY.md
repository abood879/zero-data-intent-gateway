# Security Model

## Identity and Authorization

The `/evaluate`, `/v1/evaluate`, and `/v1/governance/evaluate` endpoints require a bearer token mapped by the server-side `TOKEN_IDENTITY_MAP` environment variable. It must be a JSON object whose keys are tokens and whose values contain string `role` and `user_id` fields. For example:

```json
{
  "replace-with-a-secret-token": {
    "role": "finance_agent",
    "user_id": "finance-service"
  }
}
```

Do not commit real tokens. Keep the map in a secret manager or a protected deployment environment. A missing map causes API requests to fail closed; malformed map configuration prevents application startup. Token comparisons use `hmac.compare_digest`. Request-body `role`, `user_id`, and `max_limit` values never override the identity mapped to the bearer token.

The engine rejects tools absent from `tool_permissions`. Tool permissions and the financial role limits are server-side policy. The current limits are `finance_agent: 5000.00`, `admin: 10000.00`, and `agent: 500.00`; amounts above the configured critical financial invariant are denied. Client-supplied `max_limit` is not consulted.

## SDK Context Integrity

The SDK only verifies identity contexts with canonical JSON and HMAC-SHA256; it has no context-signing function and never auto-signs an agent identity. Unsigned or modified `__context__` values, and calls that omit context, are rejected with `IdentitySpoofingError`. The legacy `__verified_signature__` boolean is not trusted. Only a trusted identity authority may issue the `__signature__` field.

The HMAC signature protects SDK context integrity. API authorization independently derives identity from the bearer token map. The SDK verifier and trusted identity authority require `GATEWAY_CONTEXT_HMAC_SECRET`; provision it only to trusted components, never to untrusted agent callers.

DoF=1 financial policy results require a gateway-issued, HMAC-signed `step_up_approval_token` bound to the tool, canonical parameter digest, role, user ID, expiry, and a one-time nonce. With `REDIS_URL` configured, nonce consumption uses atomic Redis `SET NX` with an expiry; Redis errors fail closed, and the deployment config enables AOF with `appendfsync always`, persistence volume storage, and `noeviction`. Without Redis, the SDK uses a durable SQLite database at `STEP_UP_NONCE_DB_PATH` (default `step_up_nonces.sqlite3`), with a unique nonce constraint and an immediate transaction; this supports multiple processes sharing the same local filesystem. Keep that database on persistent shared storage for worker processes and across restarts. Do not use SQLite as a cross-host shared filesystem store; use a shared Redis service for multi-host deployments. The SDK rejects missing, expired, replayed, malformed, or mismatched approval tokens, and fails closed when nonce storage is unavailable. `max_allowed_dof` cannot override financial or security invariants; it only allows metadata explicitly classified as parameter-completion disambiguation.

## Audit Integrity and Limitations

The SDK audit ledger persists JSONL write-ahead events to `audit_ledger.jsonl` (override with `AUDIT_LEDGER_PATH`). Each SHA-256 block includes the canonical parameter digest and previous block hash. Startup verifies the existing chain and fails closed on corruption. Each authorized call writes `POLICY_EVALUATED` before execution and `EXECUTION_SUCCESS` or `EXECUTION_FAILED` afterward, including latency and a bounded exception summary. A thread lock and fsync protect in-process append/update ordering. This local WAL is not shared safely across processes or machines and is not externally immutable; use an independently protected append-only audit service when those guarantees are required.

## Deployment

Use TLS for traffic outside a trusted local environment, store bearer tokens and HMAC keys in a secret manager, and avoid logging request bodies or credentials. The gateway cannot prevent an agent process with direct vendor credentials or unrestricted egress from bypassing the protected tool decorator; enforce those boundaries in the agent runtime or orchestrator.
