import os
import functools
import inspect
from typing import Any, Callable, Optional
import requests
from app.main import evaluate_dof


class ZeroDataInterceptor:
    """Gateway-backed interceptor retained for existing SDK integrations."""

    def __init__(self, gateway_url: str = "http://127.0.0.1:8080"):
        self.gateway_url = gateway_url

    def guard(self, func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            payload = kwargs.get("payload", args[0] if args else {})
            gateway_token = os.getenv("GATEWAY_API_TOKEN")
            if not gateway_token:
                raise RuntimeError(
                    "GATEWAY_API_TOKEN must be configured before calling the gateway"
                )
            response = requests.post(
                f"{self.gateway_url}/v1/governance/evaluate",
                json=payload,
                headers={"Authorization": f"Bearer {gateway_token}"},
            )
            response.raise_for_status()
            data = response.json()

            if data.get("status") == "INTENT_LOCKED":
                return func(*args, **kwargs)
            if data.get("status") == "ACTIVE_DISAMBIGUATION_REQUIRED":
                raise ValueError(f"Ambiguity Halt: {data.get('prompt_to_user')}")
            raise PermissionError(f"Deterministic Halt: {data.get('action')}")

        return wrapper


class GatewaySecurityError(Exception):
    """Base exception for Zero-Data Intent Gateway errors."""
    pass


class SecurityViolationError(GatewaySecurityError):
    """Raised when an operation is aborted under Hard Halt (DoF >= 2)."""
    pass


class DisambiguationRequiredError(GatewaySecurityError):
    """Raised when parameters require clarification or HITL step-up (DoF = 1)."""
    def __init__(self, message: str, reasons: list[str]):
        super().__init__(message)
        self.reasons = reasons


def protected_tool(
    tool_name: Optional[str] = None,
    max_allowed_dof: int = 0
) -> Callable:
    """
    Drop-in execution decorator for AI Agent tool definitions (LangChain, CrewAI, AutoGen).
    Evaluates DoF deterministically before delegating execution to the protected callable.
    """
    def decorator(func: Callable) -> Callable:
        target_tool = tool_name or func.__name__
        signature = inspect.signature(func)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            call_kwargs = kwargs.copy()
            context = call_kwargs.pop(
                "__context__", {"role": "agent", "user_id": "system"}
            )
            bound_arguments = signature.bind(*args, **call_kwargs)
            bound_arguments.apply_defaults()
            parameters = dict(bound_arguments.arguments)
            for name, parameter in signature.parameters.items():
                if parameter.kind is inspect.Parameter.VAR_KEYWORD:
                    parameters.update(parameters.pop(name))
            payload = {
                "tool": target_tool,
                "parameters": parameters,
                "context": context,
            }
            dof, reasons = evaluate_dof(payload)

            if dof > max_allowed_dof:
                if dof == 1:
                    raise DisambiguationRequiredError(
                        f"Action halted: disambiguation or human approval required. Reasons: {reasons}",
                        reasons=reasons
                    )
                raise SecurityViolationError(
                    f"Execution blocked under fail-closed policy (DoF={dof}). Violations: {reasons}"
                )

            return func(*args, **call_kwargs)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            call_kwargs = kwargs.copy()
            context = call_kwargs.pop(
                "__context__", {"role": "agent", "user_id": "system"}
            )
            bound_arguments = signature.bind(*args, **call_kwargs)
            bound_arguments.apply_defaults()
            parameters = dict(bound_arguments.arguments)
            for name, parameter in signature.parameters.items():
                if parameter.kind is inspect.Parameter.VAR_KEYWORD:
                    parameters.update(parameters.pop(name))
            payload = {
                "tool": target_tool,
                "parameters": parameters,
                "context": context,
            }
            dof, reasons = evaluate_dof(payload)

            if dof > max_allowed_dof:
                if dof == 1:
                    raise DisambiguationRequiredError(
                        f"Action halted: disambiguation or human approval required. Reasons: {reasons}",
                        reasons=reasons
                    )
                raise SecurityViolationError(
                    f"Execution blocked under fail-closed policy (DoF={dof}). Violations: {reasons}"
                )

            return await func(*args, **call_kwargs)

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator
