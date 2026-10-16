\# Operational Reconciliation Runbook



\## 1. Architectural Model: Fail-Safe Quarantine

The Zero-Data Intent Gateway enforces a strict \*\*Fail-Safe Quarantine\*\* lifecycle. When external downstream communication drops or yields a non-final outcome (e.g., HTTP 502, timeout, or HTTP 202 without terminal success):

\- The financial reservation transitions immediately to `RECONCILIATION\_REQUIRED`.

\- All duplicate requests bearing the same `Idempotency-Key` are hard-blocked with HTTP `409 Conflict`.

\- Funds remain strictly locked in the SQLite cumulative budget ledger to prevent double-spending.



\## 2. Operator Authority \& Separation of Duties (Four-Eyes Principle)

Reconciliation cannot be performed automatically or by client agents. It requires an authorized human operator with the `reconciler` role using cryptographically verified provider proofs.



\### Reconciliation Requirements:

1\. \*\*Signed Provider Proof\*\*: An ECDSA/HMAC cryptographically signed assertion issued by the downstream financial provider certifying final disposition (`CONFIRMED\_EXECUTED` or `CONFIRMED\_NOT\_EXECUTED`).

2\. \*\*Reconciliation Nonce\*\*: A single-use monotonic nonce verified against `step\_up\_nonce\_store` to prevent proof replay.

3\. \*\*Operator Identity\*\*: Authenticated context bearing `role: reconciler` bound directly to the targeted `reservation\_id`.



\## 3. Step-by-Step Resolution Procedures



\### Scenario A: Provider Confirmed Non-Execution (`CONFIRMED\_NOT\_EXECUTED`)

1\. Obtain the cryptographically signed non-execution certificate from the provider portal or settlement ledger.

2\. Execute administrative resolution:

&#x20;  - Call `governance\_engine.reconcile\_reservation()` with disposition `CONFIRMED\_NOT\_EXECUTED`.

&#x20;  - The gateway restores the reserved budget back to the identity limit.

&#x20;  - Idempotency status transitions to `ABORTED`.

3\. Verify that the budget allocation is restored in SQLite and recorded in `budget\_reconciliation\_audit`.



\### Scenario B: Provider Confirmed Execution (`CONFIRMED\_EXECUTED`)

1\. Obtain the cryptographically signed execution receipt from the provider.

2\. Execute administrative resolution:

&#x20;  - Call `governance\_engine.reconcile\_reservation()` with disposition `CONFIRMED\_EXECUTED`.

&#x20;  - The gateway commits the reservation permanently.

&#x20;  - Idempotency status transitions to `COMMITTED`.

3\. Verify the final settlement entry in the ledger.



\## 4. Immutable Audit Verification

Every administrative intervention logs an immutable entry to `budget\_reconciliation\_audit`:

```sql

SELECT reservation\_id, operator\_id, disposition, resolved\_at, proof\_hash

FROM budget\_reconciliation\_audit

WHERE reservation\_id = ?;

