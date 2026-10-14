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

The SDK's `sign_context` and `verify_context` use canonical JSON and HMAC-SHA256. Configure `GATEWAY_CONTEXT_HMAC_SECRET` in the trusted SDK runtime and do not expose it to untrusted callers. Unsigned or modified `__context__` values are rejected with `IdentitySpoofingError`; the legacy `__verified_signature__` boolean is not trusted.

The HMAC signature protects SDK context integrity. API authorization independently derives identity from the bearer token map. A shared HMAC key is a trust credential: anyone who can use it can sign arbitrary SDK contexts, so it must remain within trusted runtimes.

## Audit Integrity and Limitations

The SDK audit ledger hashes canonicalized tool parameters into each SHA-256 block and links each block to its predecessor. A thread lock makes the in-process hash-chain update atomic across threads. This in-memory ledger is not shared across processes or machines and is not externally immutable; use an independently protected append-only audit service when those guarantees are required.

## Deployment

Use TLS for traffic outside a trusted local environment, store bearer tokens and HMAC keys in a secret manager, and avoid logging request bodies or credentials. The gateway cannot prevent an agent process with direct vendor credentials or unrestricted egress from bypassing the protected tool decorator; enforce those boundaries in the agent runtime or orchestrator.
