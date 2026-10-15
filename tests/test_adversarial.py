import asyncio
import hashlib
import json
import multiprocessing
import sqlite3
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from decimal import Decimal
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app import main as gateway_main
from app.engine import governance_engine
from app.main import app
import sdk
from sdk import (
    AuditLedger,
    AuditLedgerError,
    ConfirmedToolFailureError,
    CriticalAuditFailureError,
    DisambiguationRequiredError,
    IdentitySpoofingError,
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
    def transfer(amount: str):
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
    def execute_maintenance():
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
    def perform_transfer(amount: str):
        return "TRANSFERRED"

    with pytest.raises(SecurityViolationError):
        perform_transfer(
            amount="50000.00",
            __context__=trusted_context("finance_agent"),
        )


def test_tamper_evident_audit_ledger_records_sdk_denials():
    initial_hash = audit_ledger.last_hash

    @protected_tool(tool_name="database_drop")
    def drop_table(target: str):
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
    async def async_drop():
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
    def execute_maintenance():
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
    def execute_maintenance():
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
        "server-enforced limit (5000.00)" in item
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
    def transfer(amount: str):
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
    def transfer(amount: str):
        pytest.fail("Execution must not proceed if nonce consumption fails.")

    with pytest.raises(AuditLedgerError, match="nonce store unavailable"):
        transfer(
            amount="6000.00",
            __context__=gateway_main._issue_trusted_context(identity),
            step_up_approval_token=token,
        )


def test_max_allowed_dof_cannot_bypass_security_invariants():
    @protected_tool(tool_name="wire_transfer", max_allowed_dof=99)
    def transfer(amount: str):
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
    def failing_transfer(amount: str):
        raise ConfirmedToolFailureError("transfer failed before mutation")

    with pytest.raises(ConfirmedToolFailureError, match="before mutation"):
        failing_transfer(amount="4000.00", __context__=context)

    assert budget_reservation_statuses(budget_path, user_id) == ["RELEASED"]

    @protected_tool(tool_name="wire_transfer")
    def valid_transfer(amount: str):
        return "TRANSFERRED"

    assert valid_transfer(amount="4000.00", __context__=context) == "TRANSFERRED"
    assert set(budget_reservation_statuses(budget_path, user_id)) == {
        "RELEASED",
        "COMMITTED",
    }


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
    def timed_out_transfer(amount: str):
        raise TimeoutError("connection lost after external debit")

    with pytest.raises(TimeoutError, match="after external debit"):
        timed_out_transfer(amount="4000.00", __context__=context)

    assert budget_reservation_statuses(budget_path, user_id) == [
        "RECONCILIATION_REQUIRED"
    ]
    assert ledger.chain[-1]["status"] == "EXECUTION_UNCERTAIN"
    assert ledger.chain[-1]["decision"] == "OUTCOME_UNKNOWN"

    @protected_tool(tool_name="wire_transfer")
    def valid_transfer(amount: str):
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
    def transfer_after_expiry(amount: str):
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
    def valid_transfer(amount: str):
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
    def transfer(amount: str):
        return "TRANSFERRED"

    assert (
        transfer(
            amount="250.00",
            __context__=trusted_context("finance_agent", user_id),
        )
        == "TRANSFERRED"
    )
    assert budget_reservation_statuses(budget_path, user_id) == ["COMMITTED"]


def test_expired_reservation_locks_budget_until_resolved(tmp_path, monkeypatch):
    budget_path = tmp_path / "expired-budgets.sqlite3"
    monkeypatch.setenv(
        "GATEWAY_ROLE_BUDGET_LIMITS",
        '{"finance_agent": "10000.00"}',
    )
    monkeypatch.setenv("GATEWAY_BUDGET_RESERVATION_TTL_SECONDS", "1")
    engine = type(governance_engine)(budget_db_path=budget_path)
    accepted, _, stale_reservation_id = engine.reserve_budget(
        "finance_agent", "expired-reservation-user", Decimal("9000.00")
    )
    assert accepted and stale_reservation_id

    with sqlite3.connect(budget_path) as connection:
        connection.execute(
            "UPDATE cumulative_budget_reservations SET expires_at = 0 "
            "WHERE reservation_id = ?",
            (stale_reservation_id,),
        )

    accepted, current_total, current_reservation_id = engine.reserve_budget(
        "finance_agent", "expired-reservation-user", Decimal("2000.00")
    )
    assert not accepted
    assert current_total == Decimal("9000.00")
    assert current_reservation_id is None
    assert budget_reservation_statuses(
        budget_path, "expired-reservation-user"
    ) == ["EXPIRED_UNRESOLVED"]

    assert engine.commit_budget(stale_reservation_id)
    assert budget_reservation_statuses(
        budget_path, "expired-reservation-user"
    ) == ["COMMITTED"]
    accepted, _, _ = engine.reserve_budget(
        "finance_agent", "expired-reservation-user", Decimal("2000.00")
    )
    assert not accepted

    release_user_id = "expired-release-user"
    accepted, _, release_reservation_id = engine.reserve_budget(
        "finance_agent", release_user_id, Decimal("9000.00")
    )
    assert accepted and release_reservation_id
    with sqlite3.connect(budget_path) as connection:
        connection.execute(
            "UPDATE cumulative_budget_reservations SET expires_at = 0 "
            "WHERE reservation_id = ?",
            (release_reservation_id,),
        )
    accepted, _, _ = engine.reserve_budget(
        "finance_agent", release_user_id, Decimal("2000.00")
    )
    assert not accepted
    assert budget_reservation_statuses(budget_path, release_user_id) == [
        "EXPIRED_UNRESOLVED"
    ]
    assert engine.release_budget(release_reservation_id)
    accepted, _, new_reservation_id = engine.reserve_budget(
        "finance_agent", release_user_id, Decimal("9000.00")
    )
    assert accepted and new_reservation_id


def test_commit_resolves_expired_unresolved_budget_reservation(tmp_path):
    budget_path = tmp_path / "stale-commit-budgets.sqlite3"
    engine = type(governance_engine)(budget_db_path=budget_path)
    accepted, _, reservation_id = engine.reserve_budget(
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

    assert engine.commit_budget(reservation_id)
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
    def side_effecting_operation():
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
    def transfer(amount: str):
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
    async def transfer(amount: str):
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
    def broken_operation():
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
