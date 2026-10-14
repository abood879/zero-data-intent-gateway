import functools
import hashlib
import inspect
import json
import os
import time
from typing import Any, Callable, Dict, Optional, Tuple
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
        self.last_hash = "GENESIS_NODE_ZERO_DATA"

    def record(self, tool: str, params: dict, context: dict, status: str) -> str:
        payload = {
            "prev_hash": self.last_hash,
            "timestamp": time.time(),
            "tool": tool,
            "role": context.get("role"),
            "status": status
        }
        envelope = json.dumps(payload, sort_keys=True)
        block_hash = hashlib.sha256(envelope.encode("utf-8")).hexdigest()
        self.last_hash = block_hash
        return block_hash

audit_ledger = AuditLedger()

def protected_tool(tool_name: Optional[str] = None, max_allowed_dof: int = 0, required_role: Optional[str] = None) -> Callable:
    def decorator(func: Callable) -> Callable:
        target_tool = tool_name or func.__name__

        def extract_and_verify_context(kwargs: dict) -> dict:
            raw_context = kwargs.pop("__context__", None)
            if raw_context and not raw_context.get("__verified_signature__"):
                raise IdentitySpoofingError("Security Breach: Unsigned or untrusted context injection detected. Identity must be verified.")
            return raw_context or {
                "role": required_role or os.getenv("AGENT_ENFORCED_ROLE", "agent"),
                "user_id": os.getenv("AGENT_IDENTITY_ID", "agent_worker"),
                "__verified_signature__": True
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