# Security Model

## Threat Model & Trust Boundaries

The gateway evaluates transaction intent before an agent performs a protected action. Trust boundaries are the agent runtime to gateway API, gateway to OPA, gateway to Redis, and the deployment/telemetry plane.

| STRIDE category | Threat scenario | Controls and residual risk |
| :--- | :--- | :--- |
| Spoofing | An untrusted caller impersonates an authorized agent or policy service. | The SDK injects a bearer token from `GATEWAY_API_TOKEN`; the API compares it in constant time. OPA is not published on the host in Compose. Use TLS and managed credentials outside the local Compose setup. |
| Tampering | A caller adds policy override fields, or an attacker alters policies or audit state. | Strict Pydantic validation rejects unknown fields and coercions. Restrict policy-file and Redis administration; Redis network isolation reduces exposure but does not prevent a privileged administrator from rewriting records. |
| Repudiation | A caller disputes an evaluation or its recorded outcome. | Hash-linked audit entries record transaction ID, decision, timestamp, and digest. The chain has the backend limitations described below and is not externally immutable. |
| Information disclosure | Raw transaction data or internal policy/audit services are exposed. | The gateway does not forward data to an LLM or persist raw payloads in audit entries. Do not log request bodies; keep Redis and OPA on the internal network and protect operational telemetry. |
| Denial of service | OPA or Redis stalls or an attacker floods the gateway. | OPA and Redis operations have timeouts; configured dependency failures deny transactions. Apply rate limiting and resource limits at the ingress/orchestrator. |
| Elevation of privilege | An agent bypasses evaluation and invokes a protected tool directly. | The SDK gates decorated tool calls on `INTENT_LOCKED`. Give agents no direct vendor credentials and enforce egress/tool restrictions in the agent runtime; the gateway alone cannot restrict an unrestricted agent process. |

Compose places Redis and OPA on the control-plane network, while the gateway bridges that network and the loopback-bound caller port. The repository does not include an agent runtime, so caller egress restrictions must be enforced by its deployment platform.

The gateway validates and decides; it cannot constrain an agent process that retains direct vendor credentials or unrestricted network egress. Enforce the agent-side egress and tool-execution boundary in its runtime or orchestrator.

## Fail-Closed & Deny-by-Default

The production Compose configuration sets both `OPA_URL` and `REDIS_URL`, and requires `GATEWAY_API_TOKEN`. When configured OPA is unreachable, returns a non-200 response, or cannot be decoded, the API returns HTTP 503 and does not invoke the internal policy engine. A valid OPA response that does not allow the operation is denied. When configured Redis is unavailable at startup or an audit append fails, the API returns HTTP 503; it does not switch to an in-memory audit chain. Callers must treat every non-2xx response as a denial and must not execute the protected action.

Without `OPA_URL` or `REDIS_URL`, the application supports local development using its deterministic in-process policy engine and ephemeral in-memory audit chain. This mode is not the production fail-closed deployment. The Compose file configures both dependencies and keeps Redis and OPA off published host ports.

These guarantees are covered by `tests/test_adversarial.py`, including the OPA outage and required-audit failure paths.

## Zero-Data Processing & Auditing

- **Zero LLM ingestion:** transaction evaluation does not call or forward data to an LLM.
- **Ephemeral in-memory processing:** the gateway evaluates the validated request in process memory; it does not persist the raw request payload in its audit record. This is not a claim of secure memory erasure, and upstream proxies or caller systems must be configured not to retain request bodies.
- **Hashed state auditing:** both memory and Redis store the same hash-chain envelope. The payload itself is not retained; only its SHA-256 digest is included. The envelope contains `tx_id`, `prev_hash`, `payload_hash`, `decision`, and `timestamp`. Each field is serialized as canonical JSON (`sort_keys=true`, compact separators, UTF-8), and `hash` is the lowercase hexadecimal SHA-256 of that JSON. Verification starts with `GENESIS_BLOCK_2026_ZERO_DATA_GATEWAY` and checks each previous-hash link and envelope digest. This detects record edits that do not also replace the subsequent chain, but is not tamper-proof against an administrator who can rewrite and recompute Redis records; use externally protected, append-only retention for that threat.

## Bypass Prevention: Token Injection & Network Isolation

The SDK reads `GATEWAY_API_TOKEN` from the trusted agent runtime and sends it as `Authorization: Bearer ...`. The gateway rejects missing or invalid tokens whenever that variable is configured. The Compose deployment requires this secret to be provided and binds the published gateway port to loopback by default; do not expose it publicly without a TLS-authenticated ingress.

Compose places Redis and OPA only on an internal control-plane network, with no host-published ports. The gateway is the only service attached to both the caller-facing and control-plane networks. In production, provide the token through a secret manager, give the agent no direct vendor credentials, and apply egress/network policy that permits protected tool calls only through the gateway decision path. The repository does not include an agent runtime, so that final egress restriction must be enforced by the deployment platform.