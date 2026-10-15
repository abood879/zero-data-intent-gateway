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
from decimal import Decimal
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import redis

from app.engine import governance_engine


class GatewaySecurityError(Exception):
    pass


class SecurityViolationError(GatewaySecurityError):
    pass


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
                            "exception_summary": exception_summary,
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


def _evaluate_and_authorize(
    tool: str,
    parameters: dict[str, Any],
    identity: dict[str, Any],
    max_allowed_dof: int,
    step_up_approval_token: Any,
) -> tuple[int, list[str], str | None]:
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
    try:
        if tool == "wire_transfer" and dof < 2 and (
            not metadata.get("step_up_required") or step_up_approved
        ):
            amount = Decimal(str(parameters["amount"]))
            reserved, cumulative_total, reservation_id = governance_engine.reserve_budget(
                str(identity["role"]),
                str(identity["user_id"]),
                amount,
            )
            if not reserved:
                reasons.append(
                    "Cumulative financial budget exceeded for this identity and time window."
                )
                dof = 2
                decision = "DENIED_CUMULATIVE_BUDGET"
            else:
                metadata["cumulative_budget_total"] = str(cumulative_total)

        audit_ledger.record(
            tool,
            parameters,
            identity,
            "POLICY_EVALUATED",
            dof=dof,
            decision=decision,
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
        return dof, reasons, reservation_id
    except BaseException:
        if reservation_id:
            governance_engine.release_budget(reservation_id)
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
        try:
            audit_ledger.record(
                tool,
                parameters,
                identity,
                "EXECUTION_FAILED" if failed else "EXECUTION_SUCCESS",
                dof=dof,
                decision="FAILED" if failed else "SUCCEEDED",
                execution_latency=time.perf_counter() - started_at,
                exception_summary=(
                    {
                        "type": type(execution_error).__name__,
                        "message": str(execution_error)[:500],
                    }
                    if execution_error is not None
                    else None
                ),
            )
        except Exception as exc:
            if reservation_id:
                governance_engine.release_budget(reservation_id)
            raise CriticalAuditFailureError(
                "Execution audit could not be persisted; RECONCILIATION_REQUIRED."
            ) from exc
        if reservation_id:
            if failed:
                governance_engine.release_budget(reservation_id)
            else:
                governance_engine.commit_budget(reservation_id)
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
        try:
            audit_ledger.record(
                tool,
                parameters,
                identity,
                "EXECUTION_FAILED" if failed else "EXECUTION_SUCCESS",
                dof=dof,
                decision="FAILED" if failed else "SUCCEEDED",
                execution_latency=time.perf_counter() - started_at,
                exception_summary=(
                    {
                        "type": type(execution_error).__name__,
                        "message": str(execution_error)[:500],
                    }
                    if execution_error is not None
                    else None
                ),
            )
        except Exception as exc:
            if reservation_id:
                governance_engine.release_budget(reservation_id)
            raise CriticalAuditFailureError(
                "Execution audit could not be persisted; RECONCILIATION_REQUIRED."
            ) from exc
        if reservation_id:
            if failed:
                governance_engine.release_budget(reservation_id)
            else:
                governance_engine.commit_budget(reservation_id)
    return result


def protected_tool(
    tool_name: Optional[str] = None,
    max_allowed_dof: int = 0,
    required_role: Optional[str] = None,
) -> Callable:
    def decorator(func: Callable) -> Callable:
        target_tool = tool_name or func.__name__
        signature = inspect.signature(func)

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
            bound_args = signature.bind_partial(*args, **call_kwargs).arguments
            dof, _, reservation_id = _evaluate_and_authorize(
                target_tool,
                bound_args,
                identity,
                max_allowed_dof,
                approval_token,
            )
            return _run_with_audit(
                func,
                args,
                call_kwargs,
                target_tool,
                bound_args,
                identity,
                dof,
                reservation_id,
            )

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            call_kwargs = kwargs.copy()
            raw_context = call_kwargs.pop("__context__", None)
            identity = validate_call_identity(raw_context)
            approval_token = call_kwargs.pop("step_up_approval_token", None)
            bound_args = signature.bind_partial(*args, **call_kwargs).arguments
            dof, _, reservation_id = _evaluate_and_authorize(
                target_tool,
                bound_args,
                identity,
                max_allowed_dof,
                approval_token,
            )
            return await _run_async_with_audit(
                func,
                args,
                call_kwargs,
                target_tool,
                bound_args,
                identity,
                dof,
                reservation_id,
            )

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


class ZeroDataInterceptor:
    def __init__(self, *args, **kwargs):
        pass
