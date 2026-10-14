import functools
import hashlib
import hmac
import inspect
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

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


_used_step_up_nonces: dict[str, float] = {}
_step_up_nonce_lock = threading.Lock()


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

    with _step_up_nonce_lock:
        expired_nonces = [
            used_nonce
            for used_nonce, nonce_expiry in _used_step_up_nonces.items()
            if nonce_expiry <= time.time()
        ]
        for used_nonce in expired_nonces:
            del _used_step_up_nonces[used_nonce]
        if nonce in _used_step_up_nonces:
            return False
        _used_step_up_nonces[nonce] = float(expiry)
    return True


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

    def _load_existing_chain(self) -> None:
        if not self.path.exists():
            return
        try:
            with self.path.open("r", encoding="utf-8") as ledger_file:
                for line in ledger_file:
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise ValueError("record must be a JSON object")
                    block_hash = record.pop("hash", None)
                    if record.get("prev_hash") != self._last_hash:
                        raise ValueError("previous hash does not match")
                    expected_hash = hashlib.sha256(_canonical_json(record)).hexdigest()
                    if not isinstance(block_hash, str) or not hmac.compare_digest(
                        block_hash, expected_hash
                    ):
                        raise ValueError("record hash does not match")
                    self._last_hash = block_hash
                    self._chain.append({**record, "hash": block_hash})
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise AuditLedgerError(
                f"Audit ledger is unreadable or corrupt at {self.path}."
            ) from exc

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
            payload = {
                "prev_hash": self._last_hash,
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
            encoded_payload = _canonical_json(payload)
            block_hash = hashlib.sha256(encoded_payload).hexdigest()
            record = {**payload, "hash": block_hash}
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8", newline="\n") as ledger_file:
                    ledger_file.write(_canonical_json(record).decode("utf-8") + "\n")
                    ledger_file.flush()
                    os.fsync(ledger_file.fileno())
            except OSError as exc:
                raise AuditLedgerError(
                    f"Could not persist audit event to {self.path}."
                ) from exc

            self._chain.append(record)
            self._last_hash = block_hash
            return block_hash


audit_ledger = AuditLedger()


def _evaluate_and_authorize(
    tool: str,
    parameters: dict[str, Any],
    identity: dict[str, Any],
    max_allowed_dof: int,
    step_up_approval_token: Any,
) -> tuple[int, list[str]]:
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
    return dof, reasons


def _run_with_audit(
    func: Callable,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    tool: str,
    parameters: dict[str, Any],
    identity: dict[str, Any],
    dof: int,
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
    return result


async def _run_async_with_audit(
    func: Callable,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    tool: str,
    parameters: dict[str, Any],
    identity: dict[str, Any],
    dof: int,
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
            dof, _ = _evaluate_and_authorize(
                target_tool,
                bound_args,
                identity,
                max_allowed_dof,
                approval_token,
            )
            return _run_with_audit(
                func, args, call_kwargs, target_tool, bound_args, identity, dof
            )

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            call_kwargs = kwargs.copy()
            raw_context = call_kwargs.pop("__context__", None)
            identity = validate_call_identity(raw_context)
            approval_token = call_kwargs.pop("step_up_approval_token", None)
            bound_args = signature.bind_partial(*args, **call_kwargs).arguments
            dof, _ = _evaluate_and_authorize(
                target_tool,
                bound_args,
                identity,
                max_allowed_dof,
                approval_token,
            )
            return await _run_async_with_audit(
                func, args, call_kwargs, target_tool, bound_args, identity, dof
            )

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


class ZeroDataInterceptor:
    def __init__(self, *args, **kwargs):
        pass
