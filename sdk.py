import functools
import hashlib
import hmac
import inspect
import json
import os
import threading
import time
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

class AuditLedger:
    def __init__(self):
        self._last_hash = "GENESIS_NODE_ZERO_DATA"
        self._chain = []
        self._lock = threading.Lock()

    @property
    def last_hash(self) -> str:
        with self._lock:
            return self._last_hash

    @property
    def chain(self) -> tuple[dict, ...]:
        with self._lock:
            return tuple(dict(record) for record in self._chain)

    def record(self, tool: str, params: dict, context: dict, status: str) -> str:
        serialized_params = json.dumps(
            params,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        params_digest = hashlib.sha256(serialized_params.encode("utf-8")).hexdigest()
        with self._lock:
            payload = {
                "prev_hash": self._last_hash,
                "timestamp": time.time(),
                "tool": tool,
                "role": context.get("role"),
                "status": status,
                "params_digest": params_digest,
            }
            envelope = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            block_hash = hashlib.sha256(envelope.encode("utf-8")).hexdigest()
            self._chain.append({**payload, "hash": block_hash})
            self._last_hash = block_hash
            return block_hash

audit_ledger = AuditLedger()

def _context_secret() -> bytes:
    secret = os.getenv("GATEWAY_CONTEXT_HMAC_SECRET")
    if not secret:
        raise RuntimeError("GATEWAY_CONTEXT_HMAC_SECRET must be configured.")
    return secret.encode("utf-8")

def sign_context(context: dict) -> dict:
    signed_context = dict(context)
    signed_context.pop("__signature__", None)
    canonical_context = json.dumps(
        signed_context,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    signature = hmac.new(
        _context_secret(),
        canonical_context,
        hashlib.sha256,
    ).hexdigest()
    return {**signed_context, "__signature__": signature}

def verify_context(context: dict) -> bool:
    if not isinstance(context, dict):
        return False
    signature = context.get("__signature__")
    if (
        not isinstance(signature, str)
        or len(signature) != hashlib.sha256().digest_size * 2
        or not signature.isascii()
    ):
        return False
    unsigned_context = {
        key: value for key, value in context.items() if key != "__signature__"
    }
    try:
        canonical_context = json.dumps(
            unsigned_context,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        expected_signature = hmac.new(
            _context_secret(),
            canonical_context,
            hashlib.sha256,
        ).hexdigest()
    except (TypeError, ValueError, RuntimeError):
        return False
    try:
        return hmac.compare_digest(signature, expected_signature)
    except TypeError:
        return False

def protected_tool(tool_name: Optional[str] = None, max_allowed_dof: int = 0, required_role: Optional[str] = None) -> Callable:
    def decorator(func: Callable) -> Callable:
        target_tool = tool_name or func.__name__

        def extract_and_verify_context(kwargs: dict) -> dict:
            raw_context = kwargs.pop("__context__", None)
            if raw_context is not None:
                if not verify_context(raw_context):
                    raise IdentitySpoofingError(
                        "Security Breach: Unsigned or tampered context detected."
                    )
                return {
                    key: value
                    for key, value in raw_context.items()
                    if key != "__signature__"
                }
            context = {
                "role": required_role or os.getenv("AGENT_ENFORCED_ROLE", "agent"),
                "user_id": os.getenv("AGENT_IDENTITY_ID", "agent_worker"),
            }
            try:
                signed_context = sign_context(context)
            except RuntimeError as exc:
                raise IdentitySpoofingError(str(exc)) from exc
            return {
                key: value
                for key, value in signed_context.items()
                if key != "__signature__"
            }

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            context = extract_and_verify_context(kwargs)
            bound_args = inspect.signature(func).bind_partial(*args, **kwargs).arguments
            payload = {"tool": target_tool, "parameters": bound_args, "context": context}
            dof, reasons, _ = governance_engine.evaluate(payload)
            if dof > max_allowed_dof:
                audit_ledger.record(target_tool, bound_args, context, "DENIED")
                if dof == 1:
                    raise DisambiguationRequiredError(f"Action halted (DoF=1): {reasons}", reasons)
                raise SecurityViolationError(f"Execution blocked under fail-closed policy (DoF={dof}): {reasons}")
            audit_ledger.record(target_tool, bound_args, context, "APPROVED")
            return func(*args, **kwargs)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            context = extract_and_verify_context(kwargs)
            bound_args = inspect.signature(func).bind_partial(*args, **kwargs).arguments
            payload = {"tool": target_tool, "parameters": bound_args, "context": context}
            dof, reasons, _ = governance_engine.evaluate(payload)
            if dof > max_allowed_dof:
                audit_ledger.record(target_tool, bound_args, context, "DENIED")
                if dof == 1:
                    raise DisambiguationRequiredError(f"Action halted (DoF=1): {reasons}", reasons)
                raise SecurityViolationError(f"Execution blocked under fail-closed policy (DoF={dof}): {reasons}")
            audit_ledger.record(target_tool, bound_args, context, "APPROVED")
            return await func(*args, **kwargs)

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    return decorator

class ZeroDataInterceptor:
    def __init__(self, *args, **kwargs):
        pass