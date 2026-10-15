import functools
import fcntl
import hashlib
import hmac
import inspect
import json
import math
import os
import sqlite3
import threading
import time
import uuid
import re
from contextvars import ContextVar
from decimal import Decimal
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import redis

from app.engine import (
    BudgetStateConflictError,
    IdempotencyConflictError,
    ReconciliationProofRequiredError,
    SecurityViolationError,
    UnsupportedCurrencyError,
    governance_engine,
)

_IDEMPOTENT_TOOL_NAMES = frozenset(
    {"wire_transfer", "admin_execute", "database_drop"}
)
PHASE_PRE_DISPATCH = "PRE_DISPATCH"
PHASE_IN_FLIGHT = "IN_FLIGHT"
_execution_phase: ContextVar[str | None] = ContextVar(
    "gateway_execution_phase", default=None
)


def _mark_execution_in_flight() -> None:
    if _execution_phase.get() == PHASE_PRE_DISPATCH:
        _execution_phase.set(PHASE_IN_FLIGHT)


def _sanitize_exception_message_legacy(exception: BaseException | str) -> str:
    message = str(exception)
    summary = message.splitlines()[0] if message else ""
    patterns = (
        (re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"), "[REDACTED_CARD]"),
        (re.compile(r"(?<!\d)(?:\d[ -]?){8,12}(?!\d)"), "[REDACTED_ACCOUNT]"),
        (
            re.compile(r"(?i)\b(?:bearer\s+)[A-Za-z0-9._~+/=-]+"),
            "Bearer [REDACTED]",
        ),
        (
            re.compile(
                r"(?i)\b(?:api[_-]?key|access[_-]?token|secret|token|key)"
                r"\s*[:=]\s*[^\s,;]+"
            ),
            "[REDACTED_CREDENTIAL]",
        ),
        (
            re.compile(r"\b(?:sk|pk|ghp|gho|xox[baprs])[-_][A-Za-z0-9_-]{8,}\b", re.I),
            "[REDACTED_TOKEN]",
        ),
    )
    for pattern, replacement in patterns:
        summary = pattern.sub(replacement, summary)
    return summary[:500]


def _sanitize_exception_message(message: BaseException | str) -> str:
    summary = _sanitize_exception_message_legacy(message)
    patterns = (
        (re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"), "[REDACTED_CARD]"),
        (re.compile(r"(?<!\d)(?:\d[ -]?){8,12}(?!\d)"), "[REDACTED_ACCOUNT]"),
        (
            re.compile(r"(?i)\b(?:bearer\s+)[A-Za-z0-9._~+/=-]+"),
            "Bearer [REDACTED_CREDENTIAL]",
        ),
        (
            re.compile(
                r"(?i)\b(?:authorization|x-api-key|api[_-]?key|access[_-]?token|"
                r"refresh[_-]?token|secret|token|key|password|passwd|credential)"
                r"\b\s*[:=]\s*[\"']?[^\s,;\"']+"
            ),
            "[REDACTED_CREDENTIAL]",
        ),
        (
            re.compile(
                r"\b(?:sk|pk|ghp|gho|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{8,}\b",
                re.I,
            ),
            "[REDACTED_TOKEN]",
        ),
        (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[REDACTED_TOKEN]"),
        (
            re.compile(r"\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]{5,}\b"),
            "[REDACTED_TOKEN]",
        ),
    )
    for pattern, replacement in patterns:
        summary = pattern.sub(replacement, summary)
    return summary[:500]


def _exception_summary(exception: BaseException) -> dict[str, str]:
    return {
        "type": type(exception).__name__,
        "message": _sanitize_exception_message(exception),
    }


class GatewaySecurityError(Exception):
    pass


class ConfirmedToolFailureError(GatewaySecurityError):
    """A proven pre-execution or non-mutating tool abort safe to roll back."""


class DisambiguationRequiredError(GatewaySecurityError):
    def __init__(self, message: str, reasons: list[str]):
        super().__init__(message)
        self.reasons = reasons


class IdentitySpoofingError(GatewaySecurityError):
    pass


class AuditLedgerError(GatewaySecurityError):
    pass


class CriticalAuditFailureError(AuditLedgerError):
    def __init__(self, message: str):
        super().__init__(message)
        self.status = "RECONCILIATION_REQUIRED"
        self.reconciliation_required = True


class SecureProviderTransport:
    """Dispatch provider requests only with a gateway idempotency key."""

    def __init__(self, dispatch: Callable[..., Any]):
        self._dispatch = dispatch

    def dispatch(
        self,
        *,
        idempotency_key: str | None = None,
        headers: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
        **request_options: Any,
    ) -> Any:
        outbound_headers = dict(headers or {})
        outbound_payload = dict(payload or {})
        resolved_key = (
            idempotency_key
            or outbound_headers.get("Idempotency-Key")
            or outbound_payload.get("idempotency_key")
        )
        if not isinstance(resolved_key, str) or not resolved_key.strip():
            raise SecurityViolationError(
                "Provider dispatch requires a gateway idempotency_key."
            )
        _mark_execution_in_flight()
        outbound_headers["Idempotency-Key"] = resolved_key
        outbound_payload["idempotency_key"] = resolved_key
        return self._dispatch(
            headers=outbound_headers,
            payload=outbound_payload,
            **request_options,
        )


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _context_secret() -> bytes:
    secret = os.getenv("GATEWAY_CONTEXT_HMAC_SECRET")
    if not secret:
        raise IdentitySpoofingError(
            "GATEWAY_CONTEXT_HMAC_SECRET must be configured by the trusted identity provider."
        )
    return secret.encode("utf-8")


def verify_trusted_identity(context: Any) -> dict[str, Any]:
    if not isinstance(context, dict):
        raise IdentitySpoofingError("A trusted signed identity context is required.")

    signature = context.get("__signature__")
    if (
        not isinstance(signature, str)
        or len(signature) != hashlib.sha256().digest_size * 2
        or not signature.isascii()
    ):
        raise IdentitySpoofingError("Identity context has no valid HMAC signature.")

    unsigned_context = {
        key: value for key, value in context.items() if key != "__signature__"
    }
    if not isinstance(unsigned_context.get("role"), str) or not isinstance(
        unsigned_context.get("user_id"), str
    ):
        raise IdentitySpoofingError("Signed identity context is incomplete.")

    try:
        expected_signature = hmac.new(
            _context_secret(),
            _canonical_json(unsigned_context),
            hashlib.sha256,
        ).hexdigest()
        signature_matches = hmac.compare_digest(signature, expected_signature)
    except (TypeError, ValueError) as exc:
        raise IdentitySpoofingError("Identity context could not be verified.") from exc

    if not signature_matches:
        raise IdentitySpoofingError("Identity context HMAC does not match.")
    return unsigned_context


def _parameters_digest(parameters: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(parameters)).hexdigest()


class StepUpNonceStore:
    """Atomically consume one-time approval nonces using shared durable storage."""

    def __init__(self, path: str | Path | None = None):
        self.redis_url = os.getenv("REDIS_URL")
        self.path = Path(
            path
            or os.getenv(
                "STEP_UP_NONCE_DB_PATH",
                "step_up_nonces.sqlite3",
            )
        )
        self._redis_client = (
            redis.Redis.from_url(
                self.redis_url,
                socket_connect_timeout=5,
                socket_timeout=5,
            )
            if self.redis_url
            else None
        )
        if self._redis_client is None:
            self._initialize_sqlite()

    def _initialize_sqlite(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.path, timeout=10) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS consumed_step_up_nonces (
                        nonce_hash TEXT PRIMARY KEY,
                        expires_at REAL NOT NULL
                    )
                    """
                )
        except sqlite3.Error as exc:
            raise AuditLedgerError(
                f"Could not initialize durable step-up nonce store at {self.path}."
            ) from exc

    def consume(self, nonce: str, expires_at: float) -> bool:
        if expires_at <= time.time():
            return False
        nonce_hash = hashlib.sha256(nonce.encode("utf-8")).hexdigest()

        if self._redis_client is not None:
            ttl_seconds = max(1, math.ceil(expires_at - time.time()))
            try:
                return bool(
                    self._redis_client.set(
                        f"zero-data-gateway:step-up-nonce:{nonce_hash}",
                        "consumed",
                        nx=True,
                        ex=ttl_seconds,
                    )
                )
            except redis.RedisError as exc:
                raise AuditLedgerError(
                    "Could not atomically consume step-up approval nonce in Redis."
                ) from exc

        try:
            with sqlite3.connect(
                self.path,
                timeout=10,
                isolation_level=None,
            ) as connection:
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "DELETE FROM consumed_step_up_nonces WHERE expires_at <= ?",
                    (time.time(),),
                )
                try:
                    connection.execute(
                        """
                        INSERT INTO consumed_step_up_nonces (nonce_hash, expires_at)
                        VALUES (?, ?)
                        """,
                        (nonce_hash, expires_at),
                    )
                except sqlite3.IntegrityError:
                    connection.rollback()
                    return False
                connection.commit()
                return True
        except sqlite3.Error as exc:
            raise AuditLedgerError(
                "Could not atomically consume step-up approval nonce in SQLite."
            ) from exc

    def consume_nonce(self, nonce: str, expires_at: float) -> bool:
        return self.consume(nonce, expires_at)


step_up_nonce_store = StepUpNonceStore()


def verify_step_up_approval_token(
    token: Any,
    *,
    tool: str,
    parameters: dict[str, Any],
    identity: dict[str, Any],
) -> bool:
    if not isinstance(token, dict):
        return False

    required_fields = {
        "tool",
        "params_digest",
        "role",
        "user_id",
        "expires_at",
        "nonce",
        "signature",
    }
    if set(token) != required_fields:
        return False

    signature = token.get("signature")
    nonce = token.get("nonce")
    expiry = token.get("expires_at")
    if (
        not isinstance(signature, str)
        or len(signature) != hashlib.sha256().digest_size * 2
        or not signature.isascii()
        or not isinstance(nonce, str)
        or not nonce
        or isinstance(expiry, bool)
        or not isinstance(expiry, (int, float))
        or not math.isfinite(expiry)
        or expiry <= time.time()
        or token.get("tool") != tool
        or token.get("params_digest") != _parameters_digest(parameters)
        or token.get("role") != identity.get("role")
        or token.get("user_id") != identity.get("user_id")
    ):
        return False

    claims = {key: value for key, value in token.items() if key != "signature"}
    try:
        expected_signature = hmac.new(
            _context_secret(),
            b"step-up-approval:v1:" + _canonical_json(claims),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            return False
    except (TypeError, ValueError, IdentitySpoofingError):
        return False

    return step_up_nonce_store.consume(nonce, float(expiry))


class AuditLedger:
    GENESIS_HASH = "GENESIS_NODE_ZERO_DATA"

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path or os.getenv("AUDIT_LEDGER_PATH", "audit_ledger.jsonl"))
        self._last_hash = self.GENESIS_HASH
        self._chain: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._load_existing_chain()

    @property
    def last_hash(self) -> str:
        with self._lock:
            return self._last_hash

    @property
    def chain(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(record) for record in self._chain)

    def generate_checkpoint_proof(self) -> dict[str, Any]:
        with self._lock:
            self._load_existing_chain()
            return {
                "last_hash": self._last_hash,
                "block_sequence_index": len(self._chain),
                "timestamp_utc": datetime.now(timezone.utc).isoformat().replace(
                    "+00:00", "Z"
                ),
            }

    def _load_existing_chain(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a+", encoding="utf-8") as ledger_file:
                fcntl.flock(ledger_file.fileno(), fcntl.LOCK_SH)
                try:
                    self._chain = self._read_chain(ledger_file)
                    self._last_hash = (
                        self._chain[-1]["hash"]
                        if self._chain
                        else self.GENESIS_HASH
                    )
                finally:
                    fcntl.flock(ledger_file.fileno(), fcntl.LOCK_UN)
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise AuditLedgerError(
                f"Audit ledger is unreadable or corrupt at {self.path}."
            ) from exc

    def _read_chain(self, ledger_file) -> list[dict[str, Any]]:
        records = []
        previous_hash = self.GENESIS_HASH
        ledger_file.seek(0)
        for line in ledger_file:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("record must be a JSON object")
            block_hash = record.pop("hash", None)
            if record.get("prev_hash") != previous_hash:
                raise ValueError("previous hash does not match")
            expected_hash = hashlib.sha256(_canonical_json(record)).hexdigest()
            if not isinstance(block_hash, str) or not hmac.compare_digest(
                block_hash, expected_hash
            ):
                raise ValueError("record hash does not match")
            previous_hash = block_hash
            records.append({**record, "hash": block_hash})
        return records

    def record(
        self,
        tool: str,
        params: dict,
        context: dict,
        status: str,
        *,
        dof: int,
        decision: str,
        execution_latency: float | None = None,
        exception_summary: dict[str, str] | None = None,
        reservation_id: str | None = None,
        resolved_idempotency_key: str | None = None,
        currency: str | None = None,
    ) -> str:
        try:
            params_digest = _parameters_digest(params)
        except (TypeError, ValueError) as exc:
            raise AuditLedgerError("Audit parameters are not canonical JSON.") from exc

        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a+", encoding="utf-8", newline="\n") as ledger_file:
                    fcntl.flock(ledger_file.fileno(), fcntl.LOCK_EX)
                    try:
                        chain = self._read_chain(ledger_file)
                        previous_hash = (
                            chain[-1]["hash"] if chain else self.GENESIS_HASH
                        )
                        payload = {
                            "prev_hash": previous_hash,
                            "timestamp": time.time(),
                            "tool": tool,
                            "role": context.get("role"),
                            "user_id": context.get("user_id"),
                            "status": status,
                            "dof": dof,
                            "decision": decision,
                            "params_digest": params_digest,
                            "execution_latency": execution_latency,
                            "exception_summary": (
                                {
                                    "type": str(
                                        exception_summary.get("type", "Exception")
                                    ).splitlines()[0][:100],
                                    "message": _sanitize_exception_message(
                                        exception_summary.get("message", "")
                                    ),
                                }
                                if exception_summary is not None
                                else None
                            ),
                            "reservation_id": reservation_id,
                            "resolved_idempotency_key": resolved_idempotency_key,
                            "currency": currency,
                        }
                        block_hash = hashlib.sha256(
                            _canonical_json(payload)
                        ).hexdigest()
                        record = {**payload, "hash": block_hash}
                        ledger_file.seek(0, os.SEEK_END)
                        ledger_file.write(
                            _canonical_json(record).decode("utf-8") + "\n"
                        )
                        ledger_file.flush()
                        os.fsync(ledger_file.fileno())
                    finally:
                        fcntl.flock(ledger_file.fileno(), fcntl.LOCK_UN)
            except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
                raise AuditLedgerError(
                    f"Could not verify or persist audit event to {self.path}."
                ) from exc

            self._chain = chain + [record]
            self._last_hash = block_hash
            return block_hash


audit_ledger = AuditLedger()


def reconcile_budget_reservation(
    reservation_id: str,
    resolution: str,
    proof: dict[str, Any],
    operator_id: str,
    operator_context: Any,
) -> bool:
    operator = governance_engine.verify_operator_context(operator_context)
    operator_identity = operator["identity"]["user_id"]
    if not isinstance(operator_id, str) or operator_id != operator_identity:
        raise SecurityViolationError(
            "Operator ID must match the verified operator identity."
        )
    return governance_engine.reconcile_reservation(
        reservation_id,
        resolution,
        proof,
        operator_id,
        operator_context,
        step_up_nonce_store,
    )


def _commit_budget_after_execution(
    reservation_id: str,
    tool: str,
    parameters: dict[str, Any],
    identity: dict[str, Any],
    dof: int,
    execution_token: str | None,
    resolved_idempotency_key: str | None,
    currency: str | None,
) -> None:
    try:
        governance_engine.commit_budget(reservation_id, execution_token)
    except BudgetStateConflictError as exc:
        governance_engine.flag_for_reconciliation(reservation_id)
        try:
            audit_ledger.record(
                tool,
                parameters,
                identity,
                "COMMIT_CONFLICT_RECONCILIATION",
                dof=dof,
                decision="RECONCILIATION_REQUIRED",
                exception_summary=_exception_summary(exc),
                reservation_id=reservation_id,
                resolved_idempotency_key=resolved_idempotency_key,
                currency=currency,
            )
        except Exception as audit_exc:
            raise CriticalAuditFailureError(
                "Budget commit conflicted after execution and conflict audit failed; "
                "RECONCILIATION_REQUIRED."
            ) from audit_exc
        raise CriticalAuditFailureError(
            "Budget commit conflicted after successful execution; "
            "RECONCILIATION_REQUIRED."
        ) from exc


def _evaluate_and_authorize(
    tool: str,
    parameters: dict[str, Any],
    identity: dict[str, Any],
    max_allowed_dof: int,
    step_up_approval_token: Any,
) -> tuple[
    int,
    list[str],
    str | None,
    str | None,
    str | None,
    str | None,
    dict[str, Any] | None,
]:
    dof, reasons, metadata = governance_engine.evaluate(
        {
            "tool": tool,
            "parameters": parameters,
            "context": identity,
        }
    )
    step_up_approved = False
    if dof >= 2:
        decision = "DENIED_SECURITY_INVARIANT"
    elif dof == 1 and metadata.get("step_up_required"):
        step_up_approved = verify_step_up_approval_token(
            step_up_approval_token,
            tool=tool,
            parameters=parameters,
            identity=identity,
        )
        decision = "STEP_UP_APPROVED" if step_up_approved else "STEP_UP_REQUIRED"
    elif dof == 1 and metadata.get("disambiguation_type") == "parameter_completion":
        decision = "PARAMETER_COMPLETION"
    elif dof == 1:
        decision = "DENIED_UNCLASSIFIED_DOF"
    else:
        decision = "APPROVED"

    reservation_id = None
    execution_token = None
    resolved_idempotency_key = None
    resolved_currency = None
    cached_confirmation = None
    idempotency_registered = False
    try:
        payload_hash = _parameters_digest(parameters) if tool in _IDEMPOTENT_TOOL_NAMES else None
        if tool in _IDEMPOTENT_TOOL_NAMES:
            idempotency_key = parameters.get("idempotency_key")
            if idempotency_key is None:
                idempotency_key = uuid.uuid4().hex
            elif not isinstance(idempotency_key, str) or not idempotency_key.strip():
                raise ValueError("Idempotency key must be a non-empty string.")
            resolved_idempotency_key = idempotency_key

        if tool == "wire_transfer" and dof < 2 and (
            not metadata.get("step_up_required") or step_up_approved
        ):
            amount = Decimal(str(parameters["amount"]))
            currency = parameters.get("currency", "USD")
            if not isinstance(currency, str) or not currency.strip():
                raise UnsupportedCurrencyError("A supported currency is required.")
            currency = currency.strip().upper()
            (
                reserved,
                cumulative_total,
                reservation_id,
                execution_token,
                cached_confirmation,
            ) = governance_engine.reserve_budget_with_confirmation(
                str(identity["role"]),
                str(identity["user_id"]),
                amount,
                resolved_idempotency_key,
                currency,
                tool,
                payload_hash,
            )
            idempotency_registered = reservation_id is not None and cached_confirmation is None
            resolved_currency = currency
            if not reserved:
                reasons.append(
                    "Cumulative financial budget exceeded for this identity and time window."
                )
                dof = 2
                decision = "DENIED_CUMULATIVE_BUDGET"
            else:
                metadata["cumulative_budget_total"] = str(cumulative_total)
        elif tool in _IDEMPOTENT_TOOL_NAMES and dof < 2 and (
            not metadata.get("step_up_required") or step_up_approved
        ):
            cached_confirmation = governance_engine.register_mutation_idempotency_key(
                resolved_idempotency_key,
                tool,
                str(identity["role"]),
                str(identity["user_id"]),
                payload_hash,
            )
            idempotency_registered = cached_confirmation is None

        audit_ledger.record(
            tool,
            parameters,
            identity,
            "POLICY_EVALUATED",
            dof=dof,
            decision=decision,
            reservation_id=reservation_id,
            resolved_idempotency_key=resolved_idempotency_key,
            currency=resolved_currency,
        )

        if dof >= 2:
            raise SecurityViolationError(
                f"Execution blocked under fail-closed policy (DoF={dof}): {reasons}"
            )
        if dof == 1 and metadata.get("step_up_required"):
            if not step_up_approved:
                raise DisambiguationRequiredError(
                    f"Valid step-up approval is required (DoF=1): {reasons}",
                    reasons,
                )
        elif dof == 1 and not (
            metadata.get("disambiguation_type") == "parameter_completion"
            and max_allowed_dof >= 1
        ):
            raise DisambiguationRequiredError(
                f"Action halted pending authorized disambiguation (DoF=1): {reasons}",
                reasons,
            )
        return (
            dof,
            reasons,
            reservation_id,
            execution_token,
            resolved_idempotency_key,
            resolved_currency,
            cached_confirmation,
        )
    except BaseException:
        if reservation_id and execution_token:
            governance_engine.release_budget(reservation_id)
        elif idempotency_registered and resolved_idempotency_key:
            governance_engine.mark_idempotency_status(
                resolved_idempotency_key, "ABORTED"
            )
        raise


def _run_with_audit(
    func: Callable,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    tool: str,
    parameters: dict[str, Any],
    identity: dict[str, Any],
    dof: int,
    reservation_id: str | None,
    execution_token: str | None,
    resolved_idempotency_key: str | None,
    currency: str | None,
) -> Any:
    started_at = time.perf_counter()
    execution_error: BaseException | None = None
    result: Any = None
    try:
        result = func(*args, **kwargs)
    except BaseException as exc:
        execution_error = exc
        raise
    finally:
        failed = execution_error is not None
        confirmed_failure = (
            _execution_phase.get() == PHASE_PRE_DISPATCH
            and isinstance(execution_error, ConfirmedToolFailureError)
        )
        if reservation_id and failed:
            if confirmed_failure:
                governance_engine.release_budget(reservation_id)
            else:
                governance_engine.flag_for_reconciliation(reservation_id)
        elif failed and confirmed_failure and resolved_idempotency_key:
            governance_engine.mark_idempotency_status(
                resolved_idempotency_key, "ABORTED"
            )
        try:
            audit_ledger.record(
                tool,
                parameters,
                identity,
                (
                    "EXECUTION_FAILED"
                    if confirmed_failure
                    else "EXECUTION_UNCERTAIN"
                    if failed
                    else "EXECUTION_SUCCESS"
                ),
                dof=dof,
                decision=(
                    "FAILED"
                    if confirmed_failure
                    else "OUTCOME_UNKNOWN"
                    if failed
                    else "SUCCEEDED"
                ),
                execution_latency=time.perf_counter() - started_at,
                exception_summary=(
                    _exception_summary(execution_error)
                    if execution_error is not None
                    else None
                ),
                reservation_id=reservation_id,
                resolved_idempotency_key=resolved_idempotency_key,
                currency=currency,
            )
        except Exception as exc:
            if reservation_id and not failed:
                governance_engine.flag_for_reconciliation(reservation_id)
            raise CriticalAuditFailureError(
                "Execution audit could not be persisted; RECONCILIATION_REQUIRED."
            ) from exc
        if reservation_id and not failed:
            _commit_budget_after_execution(
                reservation_id,
                tool,
                parameters,
                identity,
                dof,
                execution_token,
                resolved_idempotency_key,
                currency,
            )
        elif not failed and resolved_idempotency_key:
            governance_engine.mark_idempotency_status(
                resolved_idempotency_key, "COMMITTED"
            )
    return result


async def _run_async_with_audit(
    func: Callable,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    tool: str,
    parameters: dict[str, Any],
    identity: dict[str, Any],
    dof: int,
    reservation_id: str | None,
    execution_token: str | None,
    resolved_idempotency_key: str | None,
    currency: str | None,
) -> Any:
    started_at = time.perf_counter()
    execution_error: BaseException | None = None
    result: Any = None
    try:
        result = await func(*args, **kwargs)
    except BaseException as exc:
        execution_error = exc
        raise
    finally:
        failed = execution_error is not None
        confirmed_failure = (
            _execution_phase.get() == PHASE_PRE_DISPATCH
            and isinstance(execution_error, ConfirmedToolFailureError)
        )
        if reservation_id and failed:
            if confirmed_failure:
                governance_engine.release_budget(reservation_id)
            else:
                governance_engine.flag_for_reconciliation(reservation_id)
        elif failed and confirmed_failure and resolved_idempotency_key:
            governance_engine.mark_idempotency_status(
                resolved_idempotency_key, "ABORTED"
            )
        try:
            audit_ledger.record(
                tool,
                parameters,
                identity,
                (
                    "EXECUTION_FAILED"
                    if confirmed_failure
                    else "EXECUTION_UNCERTAIN"
                    if failed
                    else "EXECUTION_SUCCESS"
                ),
                dof=dof,
                decision=(
                    "FAILED"
                    if confirmed_failure
                    else "OUTCOME_UNKNOWN"
                    if failed
                    else "SUCCEEDED"
                ),
                execution_latency=time.perf_counter() - started_at,
                exception_summary=(
                    _exception_summary(execution_error)
                    if execution_error is not None
                    else None
                ),
                reservation_id=reservation_id,
                resolved_idempotency_key=resolved_idempotency_key,
                currency=currency,
            )
        except Exception as exc:
            if reservation_id and not failed:
                governance_engine.flag_for_reconciliation(reservation_id)
            raise CriticalAuditFailureError(
                "Execution audit could not be persisted; RECONCILIATION_REQUIRED."
            ) from exc
        if reservation_id and not failed:
            _commit_budget_after_execution(
                reservation_id,
                tool,
                parameters,
                identity,
                dof,
                execution_token,
                resolved_idempotency_key,
                currency,
            )
        elif not failed and resolved_idempotency_key:
            governance_engine.mark_idempotency_status(
                resolved_idempotency_key, "COMMITTED"
            )
    return result


def _bound_tool_parameters(
    signature: inspect.Signature,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    bound = signature.bind_partial(*args, **kwargs)
    parameters: dict[str, Any] = {}
    for name, value in bound.arguments.items():
        parameter = signature.parameters[name]
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            parameters.update(value)
        else:
            parameters[name] = value
    return parameters


def _inject_idempotency_key(
    signature: inspect.Signature,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    idempotency_key: str | None,
) -> tuple[tuple[Any, ...], dict[str, Any]]:
    if idempotency_key is None:
        return args, kwargs
    idempotency_parameter = signature.parameters.get("idempotency_key")
    if idempotency_parameter is not None and idempotency_parameter.kind in (
        inspect.Parameter.POSITIONAL_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
    ):
        bound = signature.bind_partial(*args, **kwargs)
        bound.arguments["idempotency_key"] = idempotency_key
        return bound.args, bound.kwargs
    if any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in signature.parameters.values()
    ):
        injected_kwargs = kwargs.copy()
        injected_kwargs["idempotency_key"] = idempotency_key
        return args, injected_kwargs
    return args, kwargs


def protected_tool(
    tool_name: Optional[str] = None,
    max_allowed_dof: int = 0,
    required_role: Optional[str] = None,
) -> Callable:
    def decorator(func: Callable) -> Callable:
        target_tool = tool_name or func.__name__
        signature = inspect.signature(func)
        if target_tool in _IDEMPOTENT_TOOL_NAMES and "idempotency_key" not in signature.parameters and not any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in signature.parameters.values()
        ):
            raise SecurityViolationError(
                "Financial tools must explicitly accept 'idempotency_key' parameter to guarantee external provider propagation"
            )

        def validate_call_identity(raw_context: Any) -> dict[str, Any]:
            if raw_context is None:
                raise IdentitySpoofingError(
                    "A trusted signed identity context is required."
                )
            identity = verify_trusted_identity(raw_context)
            if required_role is not None and identity["role"] != required_role:
                raise SecurityViolationError(
                    f"Trusted identity role must be '{required_role}'."
                )
            return identity

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            call_kwargs = kwargs.copy()
            raw_context = call_kwargs.pop("__context__", None)
            identity = validate_call_identity(raw_context)
            approval_token = call_kwargs.pop("step_up_approval_token", None)
            bound_args = _bound_tool_parameters(signature, args, call_kwargs)
            (
                dof,
                _,
                reservation_id,
                execution_token,
                resolved_idempotency_key,
                currency,
                cached_confirmation,
            ) = _evaluate_and_authorize(
                target_tool,
                bound_args,
                identity,
                max_allowed_dof,
                approval_token,
            )
            if cached_confirmation is not None:
                return cached_confirmation
            phase_token = (
                _execution_phase.set(PHASE_PRE_DISPATCH)
                if _execution_phase.get() is None
                else None
            )
            try:
                try:
                    tool_args, tool_kwargs = _inject_idempotency_key(
                        signature,
                        args,
                        call_kwargs,
                        resolved_idempotency_key,
                    )
                except BaseException:
                    if reservation_id and execution_token:
                        governance_engine.release_budget(reservation_id)
                    elif resolved_idempotency_key:
                        governance_engine.mark_idempotency_status(
                            resolved_idempotency_key, "ABORTED"
                        )
                    raise
                return _run_with_audit(
                    func,
                    tool_args,
                    tool_kwargs,
                    target_tool,
                    bound_args,
                    identity,
                    dof,
                    reservation_id,
                    execution_token,
                    resolved_idempotency_key,
                    currency,
                )
            finally:
                if phase_token is not None:
                    _execution_phase.reset(phase_token)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            call_kwargs = kwargs.copy()
            raw_context = call_kwargs.pop("__context__", None)
            identity = validate_call_identity(raw_context)
            approval_token = call_kwargs.pop("step_up_approval_token", None)
            bound_args = _bound_tool_parameters(signature, args, call_kwargs)
            (
                dof,
                _,
                reservation_id,
                execution_token,
                resolved_idempotency_key,
                currency,
                cached_confirmation,
            ) = _evaluate_and_authorize(
                target_tool,
                bound_args,
                identity,
                max_allowed_dof,
                approval_token,
            )
            if cached_confirmation is not None:
                return cached_confirmation
            phase_token = (
                _execution_phase.set(PHASE_PRE_DISPATCH)
                if _execution_phase.get() is None
                else None
            )
            try:
                try:
                    tool_args, tool_kwargs = _inject_idempotency_key(
                        signature,
                        args,
                        call_kwargs,
                        resolved_idempotency_key,
                    )
                except BaseException:
                    if reservation_id and execution_token:
                        governance_engine.release_budget(reservation_id)
                    elif resolved_idempotency_key:
                        governance_engine.mark_idempotency_status(
                            resolved_idempotency_key, "ABORTED"
                        )
                    raise
                return await _run_async_with_audit(
                    func,
                    tool_args,
                    tool_kwargs,
                    target_tool,
                    bound_args,
                    identity,
                    dof,
                    reservation_id,
                    execution_token,
                    resolved_idempotency_key,
                    currency,
                )
            finally:
                if phase_token is not None:
                    _execution_phase.reset(phase_token)

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


class ZeroDataInterceptor:
    def __init__(self, *args, **kwargs):
        pass
