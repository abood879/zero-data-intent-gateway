import asyncio
import hashlib
import hmac
import json
import multiprocessing
import sqlite3
import time
import uuid
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from decimal import Decimal
from datetime import datetime, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import main as gateway_main
from app.engine import (
    BudgetStateConflictError,
    IdempotencyConflictError,
    UnsupportedCurrencyError,
    governance_engine,
)
from app.main import app
import sdk
from sdk import (
    AuditLedger,
    AuditLedgerError,
    ConfirmedToolFailureError,
    CriticalAuditFailureError,
    DisambiguationRequiredError,
    IdentitySpoofingError,
    ReconciliationProofRequiredError,
    SecurityViolationError,
    audit_ledger,
    protected_tool,
)

client = TestClient(app)
TEST_TOKEN = "adversarial-test-token"


def _append_audit_record_in_process(arguments: tuple[str, int]) -> str:
    path, index = arguments
    ledger = AuditLedger(path)
    return ledger.record(
        "wire_transfer",
        {"amount": str(index)},
        {"role": "finance_agent", "user_id": "audit-process-test"},
        "EXECUTION_SUCCESS",
        dof=0,
        decision="SUCCEEDED",
    )


def _execute_transfer_in_process(amount: str) -> bool:
    from sdk import SecurityViolationError, protected_tool

    @protected_tool(tool_name="wire_transfer")
    def transfer(amount: str, idempotency_key: str):
        return "TRANSFERRED"

    context = gateway_main._issue_trusted_context(
        {"role": "finance_agent", "user_id": "concurrent-budget-test"}
    )
    try:
        transfer(amount=amount, __context__=context)
        return True
    except SecurityViolationError:
        return False


def _consume_nonce_in_process(path: str, nonce: str, expires_at: float) -> bool:
    return sdk.StepUpNonceStore(path).consume(nonce, expires_at)


def trusted_context(role: str, user_id: str = "test-user") -> dict[str, str]:
    return gateway_main._issue_trusted_context({"role": role, "user_id": user_id})


def trusted_operator_context(
    role: str,
    user_id: str,
    target_reservation_id: str,
    expires_at: float | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    return gateway_main._issue_trusted_context(
        {
            "role": role,
            "identity": {"user_id": user_id},
            "expires_at": expires_at or time.time() + 60,
            "target_reservation_id": target_reservation_id,
            "nonce": nonce or uuid.uuid4().hex,
        }
    )


def signed_provider_proof(
    provider_status: str,
    idempotency_key: str,
    reservation_id: str,
    amount: str = "100.00",
    currency: str = "USD",
    provider_ref: str = "provider-reference-1",
) -> dict[str, str]:
    payload = {
        "provider_status": provider_status,
        "idempotency_key": idempotency_key,
        "amount": amount,
        "currency": currency,
        "provider_ref": provider_ref,
    }
    canonical_proof = (
        f"{idempotency_key}:{reservation_id}:{Decimal(amount)}:"
        f"{currency.upper()}:{provider_ref}:{provider_status}"
    )
    signature = hmac.new(
        b"test-provider-proof-secret",
        canonical_proof.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {**payload, "provider_signature": signature}


def budget_reservation_statuses(database_path, user_id: str) -> list[str]:
    with sqlite3.connect(database_path) as connection:
        rows = connection.execute(
            """
            SELECT status
            FROM cumulative_budget_reservations
            WHERE user_id = ?
            ORDER BY reserved_at, rowid
            """,
            (user_id,),
        ).fetchall()
    return [row[0] for row in rows]


@pytest.fixture(autouse=True)
def configure_security_environment(monkeypatch):
    monkeypatch.setenv("GATEWAY_CONTEXT_HMAC_SECRET", "test-context-signing-secret")
    monkeypatch.setenv(
        "GATEWAY_PROVIDER_PROOF_HMAC_SECRET",
        "test-provider-proof-secret",
    )
    monkeypatch.setattr(
        gateway_main,
        "TOKEN_IDENTITY_MAP",
        {
            TEST_TOKEN: {
                "role": "finance_agent",
                "user_id": "adversarial-test-user",
            }
        },
    )


def test_unverified_context_injection_fails_closed():
    @protected_tool(tool_name="admin_execute")
    def execute_maintenance(idempotency_key: str):
        return "RUNNING"

    with pytest.raises(IdentitySpoofingError):
        execute_maintenance(
            __context__={"role": "superadmin", "__verified_signature__": False}
        )

    with pytest.raises(IdentitySpoofingError):
        execute_maintenance()

    assert not hasattr(sdk, "sign_context")


def test_e2e_unified_engine_parity_between_sdk_and_api():
    payload = {
        "tool": "wire_transfer",
        "parameters": {"amount": "50000.00"},
        "context": {"role": "finance_agent", "max_limit": "5000.00"},
    }
    response = client.post(
        "/v1/evaluate",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
        json=payload,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "DENIED"
    assert response.json()["dof"] >= 2

    @protected_tool(tool_name="wire_transfer")
    def perform_transfer(amount: str, idempotency_key: str):
        return "TRANSFERRED"

    with pytest.raises(SecurityViolationError):
        perform_transfer(
            amount="50000.00",
            __context__=trusted_context("finance_agent"),
        )


def test_tamper_evident_audit_ledger_records_sdk_denials():
    initial_hash = audit_ledger.last_hash

    @protected_tool(tool_name="database_drop")
    def drop_table(target: str, idempotency_key: str):
        return "DROPPED"

    with pytest.raises(SecurityViolationError):
        drop_table(
            target="customers",
            __context__=trusted_context("finance_agent"),
        )
    assert audit_ledger.last_hash != initial_hash


@pytest.mark.asyncio
async def test_async_protected_tool_execution():
    @protected_tool(tool_name="database_drop")
    async def async_drop(idempotency_key: str):
        await asyncio.sleep(0.01)
        return "DONE"

    with pytest.raises(SecurityViolationError):
        await async_drop(__context__=trusted_context("agent"))


def test_unknown_tool_fails_closed_immediately():
    dof, violations, _ = governance_engine.evaluate(
        {
            "tool": "unregistered_tool",
            "parameters": {},
            "context": {"role": "agent"},
        }
    )

    assert dof >= 2
    assert violations == [
        "Security Invariant: Tool is unrecognized (Fail-Closed)"
    ]


def test_untrusted_context_spoofing_blocked_via_hmac():
    @protected_tool(tool_name="admin_execute")
    def execute_maintenance(idempotency_key: str):
        return "RUNNING"

    with pytest.raises(IdentitySpoofingError):
        execute_maintenance(
            __context__={
                "role": "admin",
                "user_id": "spoofed",
                "__verified_signature__": True,
            }
        )

    tampered_context = gateway_main._issue_trusted_context(
        {"role": "admin", "user_id": "trusted-admin"}
    )
    tampered_context["role"] = "superadmin"
    with pytest.raises(IdentitySpoofingError):
        execute_maintenance(__context__=tampered_context)


def test_valid_hmac_signed_context_authorized():
    @protected_tool(tool_name="admin_execute")
    def execute_maintenance(idempotency_key: str):
        return "RUNNING"

    context = gateway_main._issue_trusted_context(
        {"role": "admin", "user_id": "verified-admin"}
    )

    assert execute_maintenance(__context__=context) == "RUNNING"


def test_server_enforced_financial_limits_override_client_injection():
    response = client.post(
        "/v1/evaluate",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
        json={
            "tool": "wire_transfer",
            "parameters": {"amount": "6000.00"},
            "context": {
                "role": "admin",
                "user_id": "attacker",
                "max_limit": "1000000.00",
            },
        },
    )

    assert response.status_code == 200
    assert response.json()["dof"] == 1
    assert any(
        "server-enforced limit (5000 USD)" in item
        for item in response.json()["violations"]
    )


def test_tamper_evident_audit_ledger_hashes_parameters_atomically(tmp_path):
    ledger = AuditLedger(tmp_path / "audit_ledger.jsonl")
    params_a = {"amount": "100.00"}
    params_b = {"amount": "200.00"}
    first_hash = ledger.record(
        "wire_transfer",
        params_a,
        {"role": "finance_agent"},
        "POLICY_EVALUATED",
        dof=0,
        decision="APPROVED",
    )
    second_hash = ledger.record(
        "wire_transfer",
        params_b,
        {"role": "finance_agent"},
        "EXECUTION_SUCCESS",
        dof=0,
        decision="SUCCEEDED",
    )

    expected_digest = hashlib.sha256(
        json.dumps(
            params_a,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    assert ledger.chain[0]["params_digest"] == expected_digest
    assert ledger.chain[1]["prev_hash"] == first_hash
    assert second_hash != first_hash

    with ThreadPoolExecutor(max_workers=8) as executor:
        hashes = list(
            executor.map(
                lambda index: ledger.record(
                    "wire_transfer",
                    {"amount": str(index)},
                    {"role": "finance_agent"},
                    "EXECUTION_SUCCESS",
                    dof=0,
                    decision="SUCCEEDED",
                ),
                range(32),
            )
        )

    chain = ledger.chain
    assert len(hashes) == 32
    assert len({record["hash"] for record in chain}) == len(chain)
    assert all(
        chain[index]["prev_hash"] == chain[index - 1]["hash"]
        for index in range(1, len(chain))
    )
    assert ledger.last_hash == chain[-1]["hash"]


def test_audit_checkpoint_proof_identifies_verifiable_root(tmp_path):
    ledger_path = tmp_path / "checkpoint-audit.jsonl"
    ledger = AuditLedger(ledger_path)
    stale_ledger = AuditLedger(ledger_path)
    ledger.record(
        "admin_execute",
        {"operation": "checkpoint"},
        {"role": "admin", "user_id": "checkpoint-user"},
        "EXECUTION_SUCCESS",
        dof=0,
        decision="SUCCEEDED",
    )

    proof = stale_ledger.generate_checkpoint_proof()
    latest_record = ledger.chain[-1]
    payload = {
        key: value for key, value in latest_record.items() if key != "hash"
    }
    expected_root = hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()

    assert proof["block_sequence_index"] == len(ledger.chain)
    assert proof["last_hash"] == expected_root == ledger.last_hash
    timestamp = datetime.fromisoformat(
        proof["timestamp_utc"].replace("Z", "+00:00")
    )
    assert timestamp.utcoffset() == timezone.utc.utcoffset(None)


def test_audit_ledger_chain_is_continuous_across_processes(tmp_path):
    ledger_path = tmp_path / "multiprocess-audit.jsonl"
    worker_count = 4
    record_count = 32

    with multiprocessing.get_context("spawn").Pool(worker_count) as pool:
        appended_hashes = pool.map(
            _append_audit_record_in_process,
            [(str(ledger_path), index) for index in range(record_count)],
        )

    ledger = AuditLedger(ledger_path)
    records = ledger.chain
    assert len(records) == record_count
    assert len(set(appended_hashes)) == record_count
    assert all(
        record["prev_hash"]
        == (
            AuditLedger.GENESIS_HASH
            if index == 0
            else records[index - 1]["hash"]
        )
        for index, record in enumerate(records)
    )
    for record in records:
        payload = {key: value for key, value in record.items() if key != "hash"}
        expected_hash = hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        assert record["hash"] == expected_hash


def test_max_allowed_dof_does_not_bypass_financial_step_up():
    identity = gateway_main._issue_trusted_context(
        {"role": "finance_agent", "user_id": "finance-user"}
    )

    @protected_tool(tool_name="wire_transfer", max_allowed_dof=1)
    def transfer(amount: str, idempotency_key: str):
        return "TRANSFERRED"

    with pytest.raises(DisambiguationRequiredError):
        transfer(amount="6000.00", __context__=identity)

    token = gateway_main._issue_step_up_approval_token(
        tool="wire_transfer",
        parameters={"amount": "6000.00"},
        identity={"role": "finance_agent", "user_id": "finance-user"},
        expires_at=time.time() + 60,
    )
    assert (
        transfer(
            amount="6000.00",
            __context__=identity,
            step_up_approval_token=token,
        )
        == "TRANSFERRED"
    )
    assert audit_ledger.chain[-2]["decision"] == "STEP_UP_APPROVED"


def test_step_up_nonce_is_persistent_across_store_instances(tmp_path, monkeypatch):
    store_path = tmp_path / "step-up-nonces.sqlite3"
    store = sdk.StepUpNonceStore(store_path)
    monkeypatch.setattr(sdk, "step_up_nonce_store", store)
    identity = {"role": "finance_agent", "user_id": "persistent-user"}
    token = gateway_main._issue_step_up_approval_token(
        tool="wire_transfer",
        parameters={"amount": "6000.00"},
        identity=identity,
        expires_at=time.time() + 60,
    )

    assert sdk.verify_step_up_approval_token(
        token,
        tool="wire_transfer",
        parameters={"amount": "6000.00"},
        identity=identity,
    )

    reopened_store = sdk.StepUpNonceStore(store_path)
    monkeypatch.setattr(sdk, "step_up_nonce_store", reopened_store)
    assert not sdk.verify_step_up_approval_token(
        token,
        tool="wire_transfer",
        parameters={"amount": "6000.00"},
        identity=identity,
    )


def test_step_up_nonce_is_atomic_across_processes(tmp_path):
    store_path = tmp_path / "shared-step-up-nonces.sqlite3"
    sdk.StepUpNonceStore(store_path)
    expires_at = time.time() + 60
    process_context = multiprocessing.get_context("spawn")

    with ProcessPoolExecutor(
        max_workers=4,
        mp_context=process_context,
    ) as executor:
        results = list(
            executor.map(
                _consume_nonce_in_process,
                [str(store_path)] * 4,
                ["one-time-approval"] * 4,
                [expires_at] * 4,
            )
        )

    assert results.count(True) == 1
    assert results.count(False) == 3


def test_configured_redis_nonce_store_uses_atomic_set_nx(tmp_path, monkeypatch):
    calls = []

    class FakeRedis:
        def set(self, key, value, *, nx, ex):
            calls.append((key, value, nx, ex))
            return True

    monkeypatch.setenv("REDIS_URL", "redis://nonce-store.test/0")
    monkeypatch.setattr(
        sdk.redis.Redis,
        "from_url",
        staticmethod(lambda _url, **_kwargs: FakeRedis()),
    )
    database_path = tmp_path / "must-not-fall-back.sqlite3"
    store = sdk.StepUpNonceStore(database_path)

    assert store.consume("redis-backed-nonce", time.time() + 60)
    assert len(calls) == 1
    assert calls[0][1] == "consumed"
    assert calls[0][2] is True
    assert calls[0][0].startswith("zero-data-gateway:step-up-nonce:")
    assert calls[0][3] >= 1
    assert not database_path.exists()


def test_configured_redis_failure_does_not_fall_back_to_sqlite(
    tmp_path, monkeypatch
):
    class UnavailableRedis:
        def set(self, *_args, **_kwargs):
            raise sdk.redis.RedisError("Redis unavailable")

    monkeypatch.setenv("REDIS_URL", "redis://nonce-store.test/0")
    monkeypatch.setattr(
        sdk.redis.Redis,
        "from_url",
        staticmethod(lambda _url, **_kwargs: UnavailableRedis()),
    )
    database_path = tmp_path / "must-not-fall-back.sqlite3"
    store = sdk.StepUpNonceStore(database_path)

    with pytest.raises(sdk.AuditLedgerError, match="Redis"):
        store.consume("redis-backed-nonce", time.time() + 60)

    assert not database_path.exists()


def test_step_up_nonce_store_failure_fails_closed(monkeypatch):
    from sdk import AuditLedgerError

    identity = {"role": "finance_agent", "user_id": "finance-user"}
    token = gateway_main._issue_step_up_approval_token(
        tool="wire_transfer",
        parameters={"amount": "6000.00"},
        identity=identity,
        expires_at=time.time() + 60,
    )

    def unavailable_store(_nonce, _expires_at):
        raise AuditLedgerError("nonce store unavailable")

    monkeypatch.setattr(sdk.step_up_nonce_store, "consume", unavailable_store)

    @protected_tool(tool_name="wire_transfer", max_allowed_dof=1)
    def transfer(amount: str, idempotency_key: str):
        pytest.fail("Execution must not proceed if nonce consumption fails.")

    with pytest.raises(AuditLedgerError, match="nonce store unavailable"):
        transfer(
            amount="6000.00",
            __context__=gateway_main._issue_trusted_context(identity),
            step_up_approval_token=token,
        )


def test_max_allowed_dof_cannot_bypass_security_invariants():
    @protected_tool(tool_name="wire_transfer", max_allowed_dof=99)
    def transfer(amount: str, idempotency_key: str):
        return "TRANSFERRED"

    with pytest.raises(SecurityViolationError):
        transfer(
            amount="15000.00",
            __context__=trusted_context("finance_agent"),
        )


def test_concurrent_transfers_cannot_exceed_cumulative_budget(
    tmp_path, monkeypatch
):
    budget_path = tmp_path / "concurrent-budgets.sqlite3"
    monkeypatch.setenv("GATEWAY_BUDGET_DB_PATH", str(budget_path))
    monkeypatch.setenv(
        "GATEWAY_ROLE_BUDGET_LIMITS",
        '{"finance_agent": "5000.00"}',
    )
    monkeypatch.setenv("GATEWAY_BUDGET_WINDOW_SECONDS", "3600")
    from app.engine import UnifiedGovernanceEngine

    UnifiedGovernanceEngine(budget_db_path=budget_path)
    with multiprocessing.get_context("spawn").Pool(2) as pool:
        results = pool.map(
            _execute_transfer_in_process,
            ["3000.00"] * 2,
        )

    assert results.count(True) == 1
    assert results.count(False) == 1


def test_failed_transfer_releases_budget_for_next_valid_transaction(
    tmp_path, monkeypatch
):
    budget_path = tmp_path / "rollback-budgets.sqlite3"
    monkeypatch.setenv(
        "GATEWAY_ROLE_BUDGET_LIMITS",
        '{"finance_agent": "5000.00"}',
    )
    engine_type = type(governance_engine)
    engine = engine_type(budget_db_path=budget_path)
    ledger = AuditLedger(tmp_path / "rollback-audit.jsonl")
    monkeypatch.setattr(sdk, "governance_engine", engine)
    monkeypatch.setattr(sdk, "audit_ledger", ledger)
    user_id = "reservation-rollback-user"
    context = trusted_context("finance_agent", user_id)

    @protected_tool(tool_name="wire_transfer")
    def failing_transfer(amount: str, idempotency_key: str):
        raise ConfirmedToolFailureError("transfer failed before mutation")

    with pytest.raises(ConfirmedToolFailureError, match="before mutation"):
        failing_transfer(amount="4000.00", __context__=context)

    assert budget_reservation_statuses(budget_path, user_id) == ["RELEASED"]

    @protected_tool(tool_name="wire_transfer")
    def valid_transfer(amount: str, idempotency_key: str):
        return "TRANSFERRED"

    assert valid_transfer(amount="4000.00", __context__=context) == "TRANSFERRED"
    assert set(budget_reservation_statuses(budget_path, user_id)) == {
        "RELEASED",
        "COMMITTED",
    }


def test_pre_dispatch_abort_allows_same_key_retry_with_matching_payload(
    tmp_path, monkeypatch
):
    budget_path = tmp_path / "idempotency-retry-budgets.sqlite3"
    engine = type(governance_engine)(budget_db_path=budget_path)
    ledger = AuditLedger(tmp_path / "idempotency-retry-ledger.jsonl")
    monkeypatch.setattr(sdk, "governance_engine", engine)
    monkeypatch.setattr(sdk, "audit_ledger", ledger)
    calls = 0

    @protected_tool(tool_name="wire_transfer")
    def transfer(amount: str, idempotency_key: str):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ConfirmedToolFailureError("local validation rejected transfer")
        return "TRANSFERRED"

    context = trusted_context("finance_agent", "same-key-retry-user")
    arguments = {
        "amount": "100.00",
        "idempotency_key": "same-key-after-abort",
        "__context__": context,
    }
    with pytest.raises(ConfirmedToolFailureError, match="local validation"):
        transfer(**arguments)

    assert budget_reservation_statuses(
        budget_path, "same-key-retry-user"
    ) == ["RELEASED"]
    with sqlite3.connect(budget_path) as connection:
        first_reservation_id = connection.execute(
            "SELECT reservation_id FROM cumulative_budget_reservations "
            "WHERE idempotency_key IS NULL"
        ).fetchone()[0]
        registry_before_retry = connection.execute(
            "SELECT payload_hash, status FROM idempotency_registry "
            "WHERE idempotency_key = ?",
            ("same-key-after-abort",),
        ).fetchone()
    assert registry_before_retry[1] == "ABORTED"

    assert transfer(**arguments) == "TRANSFERRED"
    assert calls == 2
    with sqlite3.connect(budget_path) as connection:
        second_reservation_id, status, updated_payload_hash = connection.execute(
            """
            SELECT r.reservation_id, i.status, i.payload_hash
            FROM idempotency_registry AS i
            JOIN cumulative_budget_reservations AS r
              ON r.reservation_id = i.reservation_id
            WHERE i.idempotency_key = ?
            """,
            ("same-key-after-abort",),
        ).fetchone()
    assert second_reservation_id != first_reservation_id
    assert status == "COMMITTED"
    assert updated_payload_hash == registry_before_retry[0]


def test_confirmed_failure_after_dispatch_requires_reconciliation(
    tmp_path, monkeypatch
):
    budget_path = tmp_path / "confirmed-flight-budgets.sqlite3"
    engine = type(governance_engine)(budget_db_path=budget_path)
    ledger = AuditLedger(tmp_path / "confirmed-flight-ledger.jsonl")
    monkeypatch.setattr(sdk, "governance_engine", engine)
    monkeypatch.setattr(sdk, "audit_ledger", ledger)

    def provider_dispatch(**_):
        raise ConfirmedToolFailureError("provider response reported a failure")

    transport = sdk.SecureProviderTransport(provider_dispatch)

    @protected_tool(tool_name="wire_transfer")
    def transfer(amount: str, idempotency_key: str):
        return transport.dispatch(
            idempotency_key=idempotency_key,
            payload={"amount": amount},
        )

    user_id = "confirmed-flight-user"
    with pytest.raises(ConfirmedToolFailureError, match="provider response"):
        transfer(
            amount="100.00",
            idempotency_key="confirmed-flight-key",
            __context__=trusted_context("finance_agent", user_id),
        )

    assert budget_reservation_statuses(budget_path, user_id) == [
        "RECONCILIATION_REQUIRED"
    ]
    assert ledger.chain[-1]["status"] == "EXECUTION_UNCERTAIN"
    assert ledger.chain[-1]["decision"] == "OUTCOME_UNKNOWN"
    with sqlite3.connect(budget_path) as connection:
        assert connection.execute(
            "SELECT status FROM idempotency_registry WHERE idempotency_key = ?",
            ("confirmed-flight-key",),
        ).fetchone() == ("PENDING",)


def test_ambiguous_transfer_timeout_locks_budget(tmp_path, monkeypatch):
    budget_path = tmp_path / "ambiguous-timeout-budgets.sqlite3"
    monkeypatch.setenv(
        "GATEWAY_ROLE_BUDGET_LIMITS",
        '{"finance_agent": "5000.00"}',
    )
    engine = type(governance_engine)(budget_db_path=budget_path)
    ledger = AuditLedger(tmp_path / "ambiguous-timeout-ledger.jsonl")
    monkeypatch.setattr(sdk, "governance_engine", engine)
    monkeypatch.setattr(sdk, "audit_ledger", ledger)
    user_id = "ambiguous-timeout-user"
    context = trusted_context("finance_agent", user_id)

    @protected_tool(tool_name="wire_transfer")
    def timed_out_transfer(amount: str, idempotency_key: str):
        raise TimeoutError("connection lost after external debit")

    with pytest.raises(TimeoutError, match="after external debit"):
        timed_out_transfer(amount="4000.00", __context__=context)

    assert budget_reservation_statuses(budget_path, user_id) == [
        "RECONCILIATION_REQUIRED"
    ]
    assert ledger.chain[-1]["status"] == "EXECUTION_UNCERTAIN"
    assert ledger.chain[-1]["decision"] == "OUTCOME_UNKNOWN"

    @protected_tool(tool_name="wire_transfer")
    def valid_transfer(amount: str, idempotency_key: str):
        return "TRANSFERRED"

    with pytest.raises(SecurityViolationError, match="Cumulative financial budget"):
        valid_transfer(amount="2000.00", __context__=context)


def test_success_after_reservation_expiry_commits_without_orphaning(
    tmp_path, monkeypatch
):
    budget_path = tmp_path / "late-commit-budgets.sqlite3"
    monkeypatch.setenv(
        "GATEWAY_ROLE_BUDGET_LIMITS",
        '{"finance_agent": "5000.00"}',
    )
    engine = type(governance_engine)(budget_db_path=budget_path)
    ledger = AuditLedger(tmp_path / "late-commit-ledger.jsonl")
    monkeypatch.setattr(sdk, "governance_engine", engine)
    monkeypatch.setattr(sdk, "audit_ledger", ledger)
    user_id = "late-commit-user"
    context = trusted_context("finance_agent", user_id)

    @protected_tool(tool_name="wire_transfer")
    def transfer_after_expiry(amount: str, idempotency_key: str):
        with sqlite3.connect(budget_path) as connection:
            connection.execute(
                "UPDATE cumulative_budget_reservations SET expires_at = 0 "
                "WHERE user_id = ? AND status = 'RESERVED'",
                (user_id,),
            )
        return "TRANSFERRED"

    assert transfer_after_expiry(amount="4000.00", __context__=context) == "TRANSFERRED"

    assert budget_reservation_statuses(budget_path, user_id) == [
        "COMMITTED"
    ]
    assert ledger.chain[-1]["status"] == "EXECUTION_SUCCESS"

    @protected_tool(tool_name="wire_transfer")
    def valid_transfer(amount: str, idempotency_key: str):
        return "TRANSFERRED"

    with pytest.raises(SecurityViolationError, match="Cumulative financial budget"):
        valid_transfer(amount="2000.00", __context__=context)


def test_successful_transfer_commits_budget_reservation(tmp_path, monkeypatch):
    budget_path = tmp_path / "committed-budgets.sqlite3"
    engine = type(governance_engine)(budget_db_path=budget_path)
    ledger = AuditLedger(tmp_path / "committed-audit.jsonl")
    monkeypatch.setattr(sdk, "governance_engine", engine)
    monkeypatch.setattr(sdk, "audit_ledger", ledger)
    user_id = "reservation-commit-user"

    @protected_tool(tool_name="wire_transfer")
    def transfer(amount: str, idempotency_key: str):
        return "TRANSFERRED"

    assert (
        transfer(
            amount="250.00",
            __context__=trusted_context("finance_agent", user_id),
        )
        == "TRANSFERRED"
    )
    assert budget_reservation_statuses(budget_path, user_id) == ["COMMITTED"]


def test_duplicate_idempotency_key_is_rejected(tmp_path):
    engine = type(governance_engine)(budget_db_path=tmp_path / "idempotency.sqlite3")
    accepted, _, reservation_id, _ = engine.reserve_budget(
        "finance_agent", "idempotency-user", Decimal("10.00"), "same-key"
    )
    assert accepted and reservation_id

    with pytest.raises(IdempotencyConflictError):
        engine.reserve_budget(
            "finance_agent", "idempotency-user", Decimal("10.00"), "same-key"
        )


@pytest.mark.asyncio
async def test_protected_tool_forwards_resolved_idempotency_key(
    tmp_path, monkeypatch
):
    engine = type(governance_engine)(budget_db_path=tmp_path / "forward-key.sqlite3")
    monkeypatch.setattr(sdk, "governance_engine", engine)
    monkeypatch.setattr(
        sdk, "audit_ledger", AuditLedger(tmp_path / "forward-key-audit.jsonl")
    )
    explicit_keys = []
    positional_only_keys = []
    variadic_keys = []

    @protected_tool(tool_name="wire_transfer")
    def explicit_transfer(amount: str, idempotency_key: str):
        explicit_keys.append(idempotency_key)
        return "TRANSFERRED"

    @protected_tool(tool_name="wire_transfer")
    def positional_only_transfer(amount: str, idempotency_key: str, /):
        positional_only_keys.append(idempotency_key)
        return "TRANSFERRED"

    @protected_tool(tool_name="wire_transfer")
    async def variadic_transfer(amount: str, **kwargs):
        variadic_keys.append(kwargs["idempotency_key"])
        return "TRANSFERRED"

    assert explicit_transfer(
        amount="10.00", __context__=trusted_context("finance_agent", "explicit-key-user")
    ) == "TRANSFERRED"
    assert positional_only_transfer(
        "10.00",
        __context__=trusted_context("finance_agent", "positional-key-user"),
    ) == "TRANSFERRED"
    assert await variadic_transfer(
        amount="10.00", __context__=trusted_context("finance_agent", "kwargs-key-user")
    ) == "TRANSFERRED"
    assert len(explicit_keys) == 1 and explicit_keys[0]
    assert len(positional_only_keys) == 1 and positional_only_keys[0]
    assert len(variadic_keys) == 1 and variadic_keys[0]
    assert len({explicit_keys[0], positional_only_keys[0], variadic_keys[0]}) == 3


def test_financial_tool_requires_idempotency_key_parameter():
    with pytest.raises(
        SecurityViolationError,
        match="must explicitly accept 'idempotency_key'",
    ):
        @protected_tool(tool_name="wire_transfer")
        def unprotected_transfer(amount: str):
            return "TRANSFERRED"


def test_currency_budgets_are_isolated_and_unsupported_currency_fails_closed(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(
        "GATEWAY_ROLE_BUDGET_LIMITS",
        '{"finance_agent": {"USD": "5000.00", "JPY": "10000"}}',
    )
    engine = type(governance_engine)(budget_db_path=tmp_path / "currency-budgets.sqlite3")
    accepted, jpy_total, _, _ = engine.reserve_budget(
        "finance_agent", "currency-user", Decimal("5000"), "jpy-key", "JPY"
    )
    assert accepted and jpy_total == Decimal("5000")
    accepted, usd_total, _, _ = engine.reserve_budget(
        "finance_agent", "currency-user", Decimal("5000.00"), "usd-key", "USD"
    )
    assert accepted and usd_total == Decimal("5000.00")

    accepted, _, _, _ = engine.reserve_budget(
        "finance_agent", "currency-user", Decimal("5001"), "jpy-over-key", "JPY"
    )
    assert not accepted
    with pytest.raises(UnsupportedCurrencyError):
        engine.reserve_budget(
            "finance_agent", "currency-user", Decimal("1"), "eur-key", "EUR"
        )


def test_commits_always_require_matching_execution_token(tmp_path):
    budget_path = tmp_path / "commit-token.sqlite3"
    engine = type(governance_engine)(budget_db_path=budget_path)
    accepted, _, reservation_id, execution_token = engine.reserve_budget(
        "finance_agent", "commit-token-user", Decimal("100.00"), "commit-token-key"
    )
    assert accepted and reservation_id and execution_token

    with pytest.raises(BudgetStateConflictError):
        engine.commit_budget(reservation_id)
    with pytest.raises(BudgetStateConflictError):
        engine.commit_budget(reservation_id, "incorrect-token")
    assert budget_reservation_statuses(budget_path, "commit-token-user") == [
        "RESERVED"
    ]

    assert engine.commit_budget(reservation_id, execution_token)
    with sqlite3.connect(budget_path) as connection:
        stored_token = connection.execute(
            "SELECT execution_token FROM cumulative_budget_reservations "
            "WHERE reservation_id = ?",
            (reservation_id,),
        ).fetchone()[0]
    assert stored_token is None
    with pytest.raises(BudgetStateConflictError):
        engine.commit_budget(reservation_id, execution_token)


def test_idempotency_registry_tombstone_survives_budget_cleanup(tmp_path):
    budget_path = tmp_path / "idempotency-tombstones.sqlite3"
    engine = type(governance_engine)(budget_db_path=budget_path)
    accepted, _, reservation_id, _ = engine.reserve_budget(
        "finance_agent", "tombstone-user", Decimal("10.00"), "permanent-key"
    )
    assert accepted and reservation_id
    assert engine.release_budget(reservation_id)
    with sqlite3.connect(budget_path) as connection:
        connection.execute(
            "UPDATE cumulative_budget_reservations SET reserved_at = 0 "
            "WHERE reservation_id = ?",
            (reservation_id,),
        )
    accepted, _, _, _ = engine.reserve_budget(
        "finance_agent", "tombstone-user", Decimal("10.00"), "cleanup-trigger-key"
    )
    assert accepted
    with sqlite3.connect(budget_path) as connection:
        reservation = connection.execute(
            "SELECT 1 FROM cumulative_budget_reservations WHERE reservation_id = ?",
            (reservation_id,),
        ).fetchone()
        registry = connection.execute(
            "SELECT idempotency_key FROM idempotency_registry "
            "WHERE idempotency_key = ?",
            ("permanent-key",),
        ).fetchone()
    assert reservation is None
    assert registry == ("permanent-key",)

    accepted, _, retry_reservation_id, _ = engine.reserve_budget(
        "finance_agent", "tombstone-user", Decimal("10.00"), "permanent-key"
    )
    assert accepted and retry_reservation_id
    assert retry_reservation_id != reservation_id


def test_audit_events_include_budget_correlation_fields(tmp_path, monkeypatch):
    budget_path = tmp_path / "audit-correlation.sqlite3"
    engine = type(governance_engine)(budget_db_path=budget_path)
    ledger = AuditLedger(tmp_path / "audit-correlation.jsonl")
    monkeypatch.setattr(sdk, "governance_engine", engine)
    monkeypatch.setattr(sdk, "audit_ledger", ledger)
    user_id = "audit-correlation-user"
    idempotency_key = "audit-correlation-key"

    @protected_tool(tool_name="wire_transfer")
    def transfer(amount: str, idempotency_key: str, currency: str):
        return "TRANSFERRED"

    assert transfer(
        amount="25.00",
        idempotency_key=idempotency_key,
        currency="USD",
        __context__=trusted_context("finance_agent", user_id),
    ) == "TRANSFERRED"
    events = ledger.chain[-2:]
    assert [event["status"] for event in events] == [
        "POLICY_EVALUATED",
        "EXECUTION_SUCCESS",
    ]
    assert len({event["reservation_id"] for event in events}) == 1
    assert all(
        event["resolved_idempotency_key"] == idempotency_key
        and event["currency"] == "USD"
        for event in events
    )


def test_currency_specific_single_transaction_limits_fail_closed_or_step_up():
    dof, violations, metadata = governance_engine.evaluate(
        {
            "tool": "wire_transfer",
            "parameters": {"amount": "4900", "currency": "EUR"},
            "context": {"role": "finance_agent", "user_id": "eur-limit-user"},
        }
    )
    assert dof == 1
    assert metadata["step_up_required"] is True
    assert any("4500 EUR" in violation for violation in violations)

    dof, violations, _ = governance_engine.evaluate(
        {
            "tool": "wire_transfer",
            "parameters": {"amount": "1", "currency": "JPY"},
            "context": {"role": "finance_agent", "user_id": "unmapped-currency-user"},
        }
    )
    assert dof >= 2
    assert any("No single-transaction limit" in violation for violation in violations)


def test_critical_limits_load_dynamic_currency_settings_without_legacy_fallback(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("GATEWAY_CRITICAL_LIMIT", "1")
    monkeypatch.setenv("GATEWAY_CRITICAL_LIMIT_GBP", "7500.25")
    engine = type(governance_engine)(budget_db_path=tmp_path / "critical-limits.sqlite3")

    assert engine.critical_financial_limits["USD"] == Decimal("5000")
    assert engine.critical_financial_limits["GBP"] == Decimal("7500.25")


def test_nonfinancial_mutation_keys_are_permanently_registered(tmp_path, monkeypatch):
    budget_path = tmp_path / "mutation-idempotency.sqlite3"
    engine = type(governance_engine)(budget_db_path=budget_path)
    monkeypatch.setattr(sdk, "governance_engine", engine)
    monkeypatch.setattr(
        sdk, "audit_ledger", AuditLedger(tmp_path / "mutation-idempotency.jsonl")
    )

    executions = []

    @protected_tool(tool_name="admin_execute")
    def admin_operation(operation: str, idempotency_key: str):
        executions.append(operation)
        return operation

    context = trusted_context("admin", "mutation-admin")
    assert admin_operation(
        operation="rotate", idempotency_key="mutation-once", __context__=context
    ) == "rotate"
    cached_confirmation = admin_operation(
        operation="rotate", idempotency_key="mutation-once", __context__=context
    )
    assert cached_confirmation == {
        "status": "COMMITTED",
        "idempotency_key": "mutation-once",
        "reservation_id": None,
        "cached": True,
    }
    with pytest.raises(IdempotencyConflictError, match="different payload"):
        admin_operation(
            operation="delete",
            idempotency_key="mutation-once",
            __context__=context,
        )
    assert executions == ["rotate"]
    with sqlite3.connect(budget_path) as connection:
        entry = connection.execute(
            "SELECT tool_name, context_user_id, payload_hash, status "
            "FROM idempotency_registry "
            "WHERE idempotency_key = ?",
            ("mutation-once",),
        ).fetchone()
    assert entry[:2] == ("admin_execute", "mutation-admin")
    assert entry[2]
    assert entry[3] == "COMMITTED"


def test_secure_provider_transport_transmits_gateway_idempotency_key():
    captured = {}

    def dispatch(**request):
        captured.update(request)
        return "sent"

    transport = sdk.SecureProviderTransport(dispatch)
    assert transport.dispatch(
        idempotency_key="gateway-request-123",
        url="https://provider.example/transfer",
        headers={"Content-Type": "application/json"},
        payload={"amount": "42.00"},
    ) == "sent"
    assert captured["headers"]["Idempotency-Key"] == "gateway-request-123"
    assert captured["payload"]["idempotency_key"] == "gateway-request-123"
    with pytest.raises(SecurityViolationError, match="requires a gateway idempotency_key"):
        transport.dispatch(url="https://provider.example/transfer", payload={"amount": "1"})


def test_expired_reservation_locks_budget_until_resolved(tmp_path, monkeypatch):
    budget_path = tmp_path / "expired-budgets.sqlite3"
    monkeypatch.setenv(
        "GATEWAY_ROLE_BUDGET_LIMITS",
        '{"finance_agent": "10000.00"}',
    )
    monkeypatch.setenv("GATEWAY_BUDGET_RESERVATION_TTL_SECONDS", "1")
    engine = type(governance_engine)(budget_db_path=budget_path)
    accepted, _, stale_reservation_id, stale_execution_token = engine.reserve_budget(
        "finance_agent", "expired-reservation-user", Decimal("9000.00")
    )
    assert accepted and stale_reservation_id

    with sqlite3.connect(budget_path) as connection:
        connection.execute(
            "UPDATE cumulative_budget_reservations SET expires_at = 0 "
            "WHERE reservation_id = ?",
            (stale_reservation_id,),
        )

    accepted, current_total, current_reservation_id, _ = engine.reserve_budget(
        "finance_agent", "expired-reservation-user", Decimal("2000.00")
    )
    assert not accepted
    assert current_total == Decimal("9000.00")
    assert current_reservation_id is None
    assert budget_reservation_statuses(
        budget_path, "expired-reservation-user"
    ) == ["EXPIRED_UNRESOLVED"]

    with pytest.raises(BudgetStateConflictError):
        engine.commit_budget(stale_reservation_id)
    assert budget_reservation_statuses(
        budget_path, "expired-reservation-user"
    ) == ["EXPIRED_UNRESOLVED"]
    assert engine.commit_budget(stale_reservation_id, stale_execution_token)
    assert budget_reservation_statuses(
        budget_path, "expired-reservation-user"
    ) == ["COMMITTED"]
    accepted, _, _, _ = engine.reserve_budget(
        "finance_agent", "expired-reservation-user", Decimal("2000.00")
    )
    assert not accepted

    release_user_id = "expired-release-user"
    accepted, _, release_reservation_id, _ = engine.reserve_budget(
        "finance_agent",
        release_user_id,
        Decimal("9000.00"),
        "provider-release-123",
    )
    assert accepted and release_reservation_id
    with sqlite3.connect(budget_path) as connection:
        connection.execute(
            "UPDATE cumulative_budget_reservations SET expires_at = 0 "
            "WHERE reservation_id = ?",
            (release_reservation_id,),
        )
    accepted, _, _, _ = engine.reserve_budget(
        "finance_agent", release_user_id, Decimal("2000.00")
    )
    assert not accepted
    assert budget_reservation_statuses(budget_path, release_user_id) == [
        "EXPIRED_UNRESOLVED"
    ]
    with pytest.raises(ReconciliationProofRequiredError):
        engine.release_budget(release_reservation_id)
    assert engine.reconcile_reservation(
        release_reservation_id,
        "RELEASED",
        signed_provider_proof(
            "CONFIRMED_NOT_EXECUTED",
            "provider-release-123",
            release_reservation_id,
            "9000.00",
        ),
        "operator-1",
        trusted_operator_context(
            "reconciler", "operator-1", release_reservation_id
        ),
        sdk.step_up_nonce_store,
    )
    accepted, _, new_reservation_id, _ = engine.reserve_budget(
        "finance_agent", release_user_id, Decimal("9000.00")
    )
    assert accepted and new_reservation_id


def test_release_requires_reconciliation_proof_for_expired_reservation(
    tmp_path,
):
    budget_path = tmp_path / "proof-required-release.sqlite3"
    engine = type(governance_engine)(budget_db_path=budget_path)
    accepted, _, reservation_id, _ = engine.reserve_budget(
        "finance_agent", "proof-required-user", Decimal("100.00")
    )
    assert accepted and reservation_id

    with sqlite3.connect(budget_path) as connection:
        connection.execute(
            "UPDATE cumulative_budget_reservations SET expires_at = 0 "
            "WHERE reservation_id = ?",
            (reservation_id,),
        )
    accepted, _, _, _ = engine.reserve_budget(
        "finance_agent", "proof-required-user", Decimal("1.00")
    )
    assert accepted
    assert budget_reservation_statuses(budget_path, "proof-required-user") == [
        "EXPIRED_UNRESOLVED",
        "RESERVED",
    ]
    with pytest.raises(ReconciliationProofRequiredError):
        engine.release_budget(reservation_id)


def test_reconcile_reservation_requires_valid_proof_and_audits_resolution(
    tmp_path, monkeypatch
):
    budget_path = tmp_path / "reconciliation-audit.sqlite3"
    engine = type(governance_engine)(budget_db_path=budget_path)
    monkeypatch.setattr(sdk, "governance_engine", engine)
    accepted, _, reservation_id, _ = engine.reserve_budget(
        "finance_agent",
        "audited-reconciliation-user",
        Decimal("100.00"),
        "idem-123",
    )
    assert accepted and reservation_id
    with sqlite3.connect(budget_path) as connection:
        connection.execute(
            "UPDATE cumulative_budget_reservations "
            "SET status = 'EXPIRED_UNRESOLVED' WHERE reservation_id = ?",
            (reservation_id,),
        )

    operator_context = trusted_operator_context(
        "reconciler", "operator-1", reservation_id
    )
    with pytest.raises(ReconciliationProofRequiredError):
        sdk.reconcile_budget_reservation(
            reservation_id,
            "RELEASED",
            {"note": "checked"},
            "operator-1",
            operator_context,
        )
    with pytest.raises(SecurityViolationError, match="Operator ID"):
        sdk.reconcile_budget_reservation(
            reservation_id,
            "RELEASED",
            signed_provider_proof(
                "CONFIRMED_NOT_EXECUTED", "idem-123", reservation_id
            ),
            "someone-else",
            operator_context,
        )

    proof = signed_provider_proof(
        "CONFIRMED_NOT_EXECUTED", "idem-123", reservation_id
    )
    assert sdk.reconcile_budget_reservation(
        reservation_id, "RELEASED", proof, "operator-1", operator_context
    )
    assert budget_reservation_statuses(
        budget_path, "audited-reconciliation-user"
    ) == ["RELEASED"]
    with sqlite3.connect(budget_path) as connection:
        audit = connection.execute(
            """
            SELECT previous_status, resolution, proof_json, operator_id
            FROM budget_reconciliation_audit
            WHERE reservation_id = ?
            """,
            (reservation_id,),
        ).fetchone()
    assert audit == (
        "EXPIRED_UNRESOLVED",
        "RELEASED",
        json.dumps(proof, sort_keys=True, separators=(",", ":")),
        "operator-1",
    )


def test_unauthorized_operator_cannot_reconcile_budget_hold(
    tmp_path, monkeypatch
):
    budget_path = tmp_path / "unauthorized-reconciliation.sqlite3"
    engine = type(governance_engine)(budget_db_path=budget_path)
    monkeypatch.setattr(sdk, "governance_engine", engine)
    accepted, _, reservation_id, _ = engine.reserve_budget(
        "finance_agent",
        "unauthorized-reconciliation-user",
        Decimal("100.00"),
        "idem-unauthorized",
    )
    assert accepted and reservation_id
    with sqlite3.connect(budget_path) as connection:
        connection.execute(
            "UPDATE cumulative_budget_reservations "
            "SET status = 'RECONCILIATION_REQUIRED' WHERE reservation_id = ?",
            (reservation_id,),
        )
    proof = signed_provider_proof(
        "CONFIRMED_NOT_EXECUTED", "idem-unauthorized", reservation_id
    )

    with pytest.raises(SecurityViolationError):
        sdk.reconcile_budget_reservation(
            reservation_id,
            "RELEASED",
            proof,
            "operator-1",
            trusted_operator_context(
                "agent", "operator-1", reservation_id
            ),
        )
    with pytest.raises(SecurityViolationError):
        sdk.reconcile_budget_reservation(
            reservation_id,
            "RELEASED",
            proof,
            "operator-1",
            {"role": "reconciler", "identity": {"user_id": "operator-1"}},
        )
    assert budget_reservation_statuses(
        budget_path, "unauthorized-reconciliation-user"
    ) == ["RECONCILIATION_REQUIRED"]


def test_reconciliation_rejects_forged_or_invalid_provider_proofs(
    tmp_path, monkeypatch
):
    budget_path = tmp_path / "forged-provider-proof.sqlite3"
    engine = type(governance_engine)(budget_db_path=budget_path)
    monkeypatch.setattr(sdk, "governance_engine", engine)
    accepted, _, reservation_id, _ = engine.reserve_budget(
        "finance_agent",
        "forged-provider-proof-user",
        Decimal("100.00"),
        "idem-main",
    )
    assert accepted and reservation_id
    with sqlite3.connect(budget_path) as connection:
        connection.execute(
            "UPDATE cumulative_budget_reservations "
            "SET status = 'EXPIRED_UNRESOLVED' WHERE reservation_id = ?",
            (reservation_id,),
        )
    operator_context = trusted_operator_context(
        "governance_admin", "operator-1", reservation_id
    )
    invalid_proofs = [
        {"provider_status": "UNKNOWN", "idempotency_key": "idem-main"},
        {
            **signed_provider_proof(
                "CONFIRMED_NOT_EXECUTED", "idem-main", reservation_id
            ),
            "provider_signature": "0" * 64,
        },
        {
            "provider_status": "CONFIRMED_NOT_EXECUTED",
            "idempotency_key": "idem-main",
        },
        signed_provider_proof(
            "CONFIRMED_NOT_EXECUTED",
            "idem-main",
            reservation_id,
            amount="101.00",
        ),
        signed_provider_proof(
            "CONFIRMED_NOT_EXECUTED",
            "idem-main",
            reservation_id,
            currency="EUR",
        ),
        signed_provider_proof(
            "CONFIRMED_NOT_EXECUTED",
            "idem-main",
            reservation_id,
            provider_ref="",
        ),
    ]
    for proof in invalid_proofs:
        with pytest.raises(ReconciliationProofRequiredError):
            sdk.reconcile_budget_reservation(
                reservation_id,
                "RELEASED",
                proof,
                "operator-1",
                operator_context,
            )
    assert budget_reservation_statuses(
        budget_path, "forged-provider-proof-user"
    ) == ["EXPIRED_UNRESOLVED"]
    hash_payload = signed_provider_proof(
        "CONFIRMED_NOT_EXECUTED", "idem-main", reservation_id
    )
    hash_only_proof = {
        key: value
        for key, value in hash_payload.items()
        if key != "provider_signature"
    }
    hash_only_proof["proof_payload_hash"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in hash_only_proof.items() if key != "proof_payload_hash"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    with pytest.raises(ReconciliationProofRequiredError):
        sdk.reconcile_budget_reservation(
            reservation_id,
            "RELEASED",
            hash_only_proof,
            "operator-1",
            operator_context,
        )


def test_provider_proof_cannot_be_replayed_across_reservations(
    tmp_path, monkeypatch
):
    budget_path = tmp_path / "proof-replay-budgets.sqlite3"
    engine = type(governance_engine)(budget_db_path=budget_path)
    monkeypatch.setattr(sdk, "governance_engine", engine)
    reservation_ids = {}
    for label in ("A", "B"):
        accepted, _, reservation_id, _ = engine.reserve_budget(
            "finance_agent",
            "proof-replay-user",
            Decimal("100.00"),
            f"idempotency-key-{label}",
        )
        assert accepted and reservation_id
        reservation_ids[label] = reservation_id
        with sqlite3.connect(budget_path) as connection:
            connection.execute(
                "UPDATE cumulative_budget_reservations "
                "SET status = 'EXPIRED_UNRESOLVED' WHERE reservation_id = ?",
                (reservation_id,),
            )

    operator_id = "replay-operator"
    operator_context_b = trusted_operator_context(
        "reconciler", operator_id, reservation_ids["B"]
    )
    proof_a = signed_provider_proof(
        "CONFIRMED_EXECUTED",
        "idempotency-key-A",
        reservation_ids["A"],
    )
    with pytest.raises(ReconciliationProofRequiredError, match="does not match"):
        sdk.reconcile_budget_reservation(
            reservation_ids["B"],
            "COMMITTED",
            proof_a,
            operator_id,
            operator_context_b,
        )
    assert budget_reservation_statuses(budget_path, "proof-replay-user") == [
        "EXPIRED_UNRESOLVED",
        "EXPIRED_UNRESOLVED",
    ]

    operator_context_a = trusted_operator_context(
        "reconciler", operator_id, reservation_ids["A"]
    )
    assert sdk.reconcile_budget_reservation(
        reservation_ids["A"],
        "COMMITTED",
        proof_a,
        operator_id,
        operator_context_a,
    )
    with sqlite3.connect(budget_path) as connection:
        committed_at = connection.execute(
            "SELECT committed_at FROM cumulative_budget_reservations "
            "WHERE reservation_id = ?",
            (reservation_ids["A"],),
        ).fetchone()[0]
    settlement = datetime.fromisoformat(committed_at.replace("Z", "+00:00"))
    assert (datetime.now(timezone.utc) - settlement).total_seconds() < 60


def test_expired_operator_context_and_operator_id_mismatch_rejected(
    tmp_path, monkeypatch
):
    budget_path = tmp_path / "expired-operator-budgets.sqlite3"
    engine = type(governance_engine)(budget_db_path=budget_path)
    monkeypatch.setattr(sdk, "governance_engine", engine)
    accepted, _, reservation_id, _ = engine.reserve_budget(
        "finance_agent",
        "expired-operator-user",
        Decimal("100.00"),
        "expired-operator-idem",
    )
    assert accepted and reservation_id
    with sqlite3.connect(budget_path) as connection:
        connection.execute(
            "UPDATE cumulative_budget_reservations "
            "SET status = 'RECONCILIATION_REQUIRED' WHERE reservation_id = ?",
            (reservation_id,),
        )
    proof = signed_provider_proof(
        "CONFIRMED_NOT_EXECUTED",
        "expired-operator-idem",
        reservation_id,
    )

    with pytest.raises(SecurityViolationError, match="expired"):
        sdk.reconcile_budget_reservation(
            reservation_id,
            "RELEASED",
            proof,
            "operator-1",
            trusted_operator_context(
                "reconciler",
                "operator-1",
                reservation_id,
                expires_at=time.time() - 1,
            ),
        )
    with pytest.raises(SecurityViolationError, match="Operator ID"):
        sdk.reconcile_budget_reservation(
            reservation_id,
            "RELEASED",
            proof,
            "different-operator",
            trusted_operator_context(
                "reconciler", "operator-1", reservation_id
            ),
        )
    assert budget_reservation_statuses(
        budget_path, "expired-operator-user"
    ) == ["RECONCILIATION_REQUIRED"]


def test_operator_context_cannot_target_another_reservation(tmp_path, monkeypatch):
    budget_path = tmp_path / "operator-scope-budgets.sqlite3"
    engine = type(governance_engine)(budget_db_path=budget_path)
    monkeypatch.setattr(sdk, "governance_engine", engine)
    accepted, _, reservation_id, _ = engine.reserve_budget(
        "finance_agent",
        "operator-scope-user",
        Decimal("100.00"),
        "operator-scope-idem",
    )
    assert accepted and reservation_id
    with sqlite3.connect(budget_path) as connection:
        connection.execute(
            "UPDATE cumulative_budget_reservations "
            "SET status = 'EXPIRED_UNRESOLVED' WHERE reservation_id = ?",
            (reservation_id,),
        )
    proof = signed_provider_proof(
        "CONFIRMED_NOT_EXECUTED", "operator-scope-idem", reservation_id
    )

    with pytest.raises(SecurityViolationError, match="not scoped"):
        sdk.reconcile_budget_reservation(
            reservation_id,
            "RELEASED",
            proof,
            "operator-1",
            trusted_operator_context("reconciler", "operator-1", "another-id"),
        )
    assert budget_reservation_statuses(budget_path, "operator-scope-user") == [
        "EXPIRED_UNRESOLVED"
    ]


def test_operator_nonce_replay_is_rejected(tmp_path, monkeypatch):
    budget_path = tmp_path / "operator-nonce-replay.sqlite3"
    engine = type(governance_engine)(budget_db_path=budget_path)
    monkeypatch.setattr(sdk, "governance_engine", engine)
    reservations = {}
    for suffix in ("A", "B"):
        accepted, _, reservation_id, _ = engine.reserve_budget(
            "finance_agent",
            "operator-nonce-user",
            Decimal("100.00"),
            f"operator-nonce-idem-{suffix}",
        )
        assert accepted and reservation_id
        reservations[suffix] = reservation_id
        with sqlite3.connect(budget_path) as connection:
            connection.execute(
                "UPDATE cumulative_budget_reservations "
                "SET status = 'RECONCILIATION_REQUIRED' "
                "WHERE reservation_id = ?",
                (reservation_id,),
            )

    nonce = uuid.uuid4().hex
    first_context = trusted_operator_context(
        "reconciler", "operator-1", reservations["A"], nonce=nonce
    )
    first_proof = signed_provider_proof(
        "CONFIRMED_NOT_EXECUTED",
        "operator-nonce-idem-A",
        reservations["A"],
    )
    assert sdk.reconcile_budget_reservation(
        reservations["A"],
        "RELEASED",
        first_proof,
        "operator-1",
        first_context,
    )

    replay_context = trusted_operator_context(
        "reconciler", "operator-1", reservations["B"], nonce=nonce
    )
    replay_proof = signed_provider_proof(
        "CONFIRMED_NOT_EXECUTED",
        "operator-nonce-idem-B",
        reservations["B"],
    )
    with pytest.raises(SecurityViolationError, match="already been consumed"):
        sdk.reconcile_budget_reservation(
            reservations["B"],
            "RELEASED",
            replay_proof,
            "operator-1",
            replay_context,
        )
    assert budget_reservation_statuses(budget_path, "operator-nonce-user") == [
        "RELEASED",
        "RECONCILIATION_REQUIRED",
    ]


def test_committed_window_rolls_but_unresolved_holds_do_not(
    tmp_path, monkeypatch
):
    budget_path = tmp_path / "dual-window-budgets.sqlite3"
    monkeypatch.setenv("GATEWAY_BUDGET_WINDOW_SECONDS", "60")
    monkeypatch.setenv(
        "GATEWAY_ROLE_BUDGET_LIMITS",
        '{"finance_agent": "10000.00"}',
    )
    engine = type(governance_engine)(budget_db_path=budget_path)

    committed_user = "old-committed-user"
    accepted, _, committed_id, committed_execution_token = engine.reserve_budget(
        "finance_agent", committed_user, Decimal("10000.00")
    )
    assert accepted and committed_id
    assert engine.commit_budget(committed_id, committed_execution_token)
    with sqlite3.connect(budget_path) as connection:
        connection.execute(
            """
            UPDATE cumulative_budget_reservations
            SET reserved_at = 0, committed_at = '1970-01-01T00:00:00Z'
            WHERE reservation_id = ?
            """,
            (committed_id,),
        )
    accepted, _, replacement_id, _ = engine.reserve_budget(
        "finance_agent", committed_user, Decimal("10000.00")
    )
    assert accepted and replacement_id

    unresolved_user = "old-unresolved-user"
    accepted, _, unresolved_id, _ = engine.reserve_budget(
        "finance_agent", unresolved_user, Decimal("10000.00")
    )
    assert accepted and unresolved_id
    with sqlite3.connect(budget_path) as connection:
        connection.execute(
            """
            UPDATE cumulative_budget_reservations
            SET reserved_at = 0, expires_at = 0
            WHERE reservation_id = ?
            """,
            (unresolved_id,),
        )
    accepted, total, rejected_id, _ = engine.reserve_budget(
        "finance_agent", unresolved_user, Decimal("1.00")
    )
    assert not accepted
    assert total == Decimal("10000.00")
    assert rejected_id is None
    assert budget_reservation_statuses(budget_path, unresolved_user) == [
        "EXPIRED_UNRESOLVED"
    ]


def test_settlement_time_controls_committed_budget_window(tmp_path, monkeypatch):
    budget_path = tmp_path / "settlement-window-budgets.sqlite3"
    monkeypatch.setenv("GATEWAY_BUDGET_WINDOW_SECONDS", "3600")
    monkeypatch.setenv(
        "GATEWAY_ROLE_BUDGET_LIMITS",
        '{"finance_agent": "10000.00"}',
    )
    engine = type(governance_engine)(budget_db_path=budget_path)
    user_id = "settlement-window-user"
    accepted, _, reservation_id, execution_token = engine.reserve_budget(
        "finance_agent", user_id, Decimal("10000.00")
    )
    assert accepted and reservation_id

    with sqlite3.connect(budget_path) as connection:
        connection.execute(
            "UPDATE cumulative_budget_reservations SET reserved_at = ? "
            "WHERE reservation_id = ?",
            (time.time() - 7200, reservation_id),
        )

    assert engine.commit_budget(reservation_id, execution_token)
    with sqlite3.connect(budget_path) as connection:
        committed_at = connection.execute(
            "SELECT committed_at FROM cumulative_budget_reservations "
            "WHERE reservation_id = ?",
            (reservation_id,),
        ).fetchone()[0]
    settlement = datetime.fromisoformat(committed_at.replace("Z", "+00:00"))
    assert (datetime.now(timezone.utc) - settlement).total_seconds() < 60

    accepted, current_total, new_reservation_id, _ = engine.reserve_budget(
        "finance_agent", user_id, Decimal("1.00")
    )
    assert not accepted
    assert current_total == Decimal("10000.00")
    assert new_reservation_id is None


def test_commit_resolves_expired_unresolved_budget_reservation(tmp_path):
    budget_path = tmp_path / "stale-commit-budgets.sqlite3"
    engine = type(governance_engine)(budget_db_path=budget_path)
    accepted, _, reservation_id, execution_token = engine.reserve_budget(
        "finance_agent", "stale-commit-user", Decimal("100.00")
    )
    assert accepted and reservation_id

    with sqlite3.connect(budget_path) as connection:
        connection.execute(
            "UPDATE cumulative_budget_reservations "
            "SET status = 'EXPIRED_UNRESOLVED' "
            "WHERE reservation_id = ?",
            (reservation_id,),
        )

    assert engine.commit_budget(reservation_id, execution_token)
    assert budget_reservation_statuses(budget_path, "stale-commit-user") == [
        "COMMITTED"
    ]


def test_successful_execution_with_failed_audit_requires_reconciliation(
    tmp_path, monkeypatch
):
    ledger = AuditLedger(tmp_path / "critical-audit.jsonl")
    monkeypatch.setattr(sdk, "audit_ledger", ledger)
    original_record = ledger.record

    def fail_success_record(*args, **kwargs):
        if args[3] == "EXECUTION_SUCCESS":
            raise AuditLedgerError("success event could not be persisted")
        return original_record(*args, **kwargs)

    monkeypatch.setattr(ledger, "record", fail_success_record)
    executed = []

    @protected_tool(tool_name="admin_execute")
    def side_effecting_operation(idempotency_key: str):
        executed.append(True)
        return "COMPLETED"

    with pytest.raises(CriticalAuditFailureError, match="RECONCILIATION_REQUIRED") as exc:
        side_effecting_operation(
            __context__=gateway_main._issue_trusted_context(
                {"role": "admin", "user_id": "audit-failure-user"}
            )
        )

    assert executed == [True]
    assert exc.value.status == "RECONCILIATION_REQUIRED"
    assert exc.value.reconciliation_required is True


def test_successful_transfer_with_audit_failure_locks_cumulative_budget(
    tmp_path, monkeypatch
):
    budget_path = tmp_path / "audit-failure-budgets.sqlite3"
    monkeypatch.setenv(
        "GATEWAY_ROLE_BUDGET_LIMITS",
        '{"finance_agent": "5000.00"}',
    )
    engine = type(governance_engine)(budget_db_path=budget_path)
    ledger = AuditLedger(tmp_path / "audit-failure-budget-ledger.jsonl")
    original_record = ledger.record
    monkeypatch.setattr(sdk, "governance_engine", engine)
    monkeypatch.setattr(sdk, "audit_ledger", ledger)
    user_id = "audit-failure-budget-user"
    context = trusted_context("finance_agent", user_id)

    def fail_success_record(*args, **kwargs):
        if args[3] == "EXECUTION_SUCCESS":
            raise AuditLedgerError("success event could not be persisted")
        return original_record(*args, **kwargs)

    monkeypatch.setattr(ledger, "record", fail_success_record)

    @protected_tool(tool_name="wire_transfer")
    def transfer(amount: str, idempotency_key: str):
        return "TRANSFERRED"

    with pytest.raises(CriticalAuditFailureError, match="RECONCILIATION_REQUIRED"):
        transfer(amount="4000.00", __context__=context)

    assert budget_reservation_statuses(budget_path, user_id) == [
        "RECONCILIATION_REQUIRED"
    ]
    with sqlite3.connect(budget_path) as connection:
        connection.execute(
            "UPDATE cumulative_budget_reservations SET reserved_at = 0 "
            "WHERE user_id = ?",
            (user_id,),
        )

    with pytest.raises(SecurityViolationError, match="Cumulative financial budget"):
        transfer(amount="2000.00", __context__=context)
    assert budget_reservation_statuses(budget_path, user_id) == [
        "RECONCILIATION_REQUIRED"
    ]


@pytest.mark.asyncio
async def test_async_success_with_audit_failure_flags_reconciliation(
    tmp_path, monkeypatch
):
    budget_path = tmp_path / "async-audit-failure-budgets.sqlite3"
    engine = type(governance_engine)(budget_db_path=budget_path)
    ledger = AuditLedger(tmp_path / "async-audit-failure-ledger.jsonl")
    original_record = ledger.record
    monkeypatch.setattr(sdk, "governance_engine", engine)
    monkeypatch.setattr(sdk, "audit_ledger", ledger)
    user_id = "async-audit-failure-user"

    def fail_success_record(*args, **kwargs):
        if args[3] == "EXECUTION_SUCCESS":
            raise AuditLedgerError("success event could not be persisted")
        return original_record(*args, **kwargs)

    monkeypatch.setattr(ledger, "record", fail_success_record)

    @protected_tool(tool_name="wire_transfer")
    async def transfer(amount: str, idempotency_key: str):
        return "TRANSFERRED"

    with pytest.raises(CriticalAuditFailureError, match="RECONCILIATION_REQUIRED"):
        await transfer(
            amount="4000.00",
            __context__=trusted_context("finance_agent", user_id),
        )

    assert budget_reservation_statuses(budget_path, user_id) == [
        "RECONCILIATION_REQUIRED"
    ]


def test_tool_execution_failure_is_written_to_persistent_ledger(
    tmp_path, monkeypatch
):
    import sdk

    ledger_path = tmp_path / "audit_ledger.jsonl"
    ledger = AuditLedger(ledger_path)
    monkeypatch.setattr(sdk, "audit_ledger", ledger)
    context = gateway_main._issue_trusted_context(
        {"role": "admin", "user_id": "admin-user"}
    )

    @protected_tool(tool_name="admin_execute")
    def broken_operation(idempotency_key: str):
        raise ValueError("execution failed for test")

    with pytest.raises(ValueError, match="execution failed for test"):
        broken_operation(__context__=context)

    events = [json.loads(line) for line in ledger_path.read_text().splitlines()]
    assert [event["status"] for event in events] == [
        "POLICY_EVALUATED",
        "EXECUTION_UNCERTAIN",
    ]
    assert events[-1]["decision"] == "OUTCOME_UNKNOWN"
    assert events[-1]["exception_summary"] == {
        "type": "ValueError",
        "message": "execution failed for test",
    }
    assert events[-1]["execution_latency"] >= 0


def test_exception_account_number_is_redacted_in_persistent_audit_ledger(
    tmp_path, monkeypatch
):
    ledger_path = tmp_path / "redacted-exception-audit.jsonl"
    ledger = AuditLedger(ledger_path)
    monkeypatch.setattr(sdk, "audit_ledger", ledger)

    @protected_tool(tool_name="admin_execute")
    def broken_operation(idempotency_key: str):
        raise ValueError(
            "provider rejected account 123456789012\n"
            "Traceback (most recent call last): raw stack detail"
        )

    with pytest.raises(ValueError):
        broken_operation(
            idempotency_key="redacted-exception-key",
            __context__=trusted_context("admin", "redacted-exception-user"),
        )

    events = [json.loads(line) for line in ledger_path.read_text().splitlines()]
    exception_summary = events[-1]["exception_summary"]
    assert exception_summary == {
        "type": "ValueError",
        "message": "provider rejected account [REDACTED_ACCOUNT]",
    }
    assert "123456789012" not in ledger_path.read_text()
    assert "Traceback" not in ledger_path.read_text()


def test_persistent_audit_chain_continues_across_instances(tmp_path):
    ledger_path = tmp_path / "audit_ledger.jsonl"
    first = AuditLedger(ledger_path)
    first_hash = first.record(
        "admin_execute",
        {"operation": "first"},
        {"role": "admin", "user_id": "admin-user"},
        "POLICY_EVALUATED",
        dof=0,
        decision="APPROVED",
    )

    resumed = AuditLedger(ledger_path)
    assert resumed.last_hash == first_hash
    second_hash = resumed.record(
        "admin_execute",
        {"operation": "second"},
        {"role": "admin", "user_id": "admin-user"},
        "EXECUTION_SUCCESS",
        dof=0,
        decision="SUCCEEDED",
        execution_latency=0.01,
    )

    verified = AuditLedger(ledger_path)
    assert verified.last_hash == second_hash
    assert len(verified.chain) == 2
    assert verified.chain[1]["prev_hash"] == first_hash


def test_api_ignores_client_supplied_identity_on_legacy_path():
    response = client.post(
        "/v1/evaluate",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
        json={
            "tool": "wire_transfer",
            "parameters": {"amount": "6000.00"},
            "context": {
                "role": "admin",
                "user_id": "attacker",
                "max_limit": "1000000.00",
            },
        },
    )

    assert response.status_code == 200
    assert response.json()["dof"] == 1


def test_legacy_evaluate_route_derives_identity_from_token_mapping():
    response = client.post(
        "/v1/governance/evaluate",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
        json={
            "id": "TX-LEGACY-IDENTITY",
            "amount": 6000.0,
            "vendor": "AWS_Cloud_Global",
            "department": "Finance",
            "budget_cleared": True,
        },
    )

    assert response.status_code == 200
    assert response.json()["degrees_of_freedom"] == 1


def test_evaluate_alias_uses_server_token_identity():
    response = client.post(
        "/evaluate",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
        json={
            "tool": "wire_transfer",
            "parameters": {"amount": "6000.00"},
            "context": {"role": "admin", "max_limit": "999999.00"},
        },
    )

    assert response.status_code == 200
    assert response.json()["dof"] == 1
