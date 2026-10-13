import requests
from functools import wraps

class ZeroDataInterceptor:
    """
    Middleware SDK for LangChain, CrewAI, and Autonomous Agents.
    Enforces deterministic boundary checks before tool execution.
    """
    def __init__(self, gateway_url: str = "http://127.0.0.1:8080"):
        self.gateway_url = gateway_url

    def guard(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            payload = kwargs.get("payload", args[0] if args else {})
            response = requests.post(
                f"{self.gateway_url}/v1/governance/evaluate",
                json=payload
            )
            data = response.json()
            
            if data.get("status") == "APPROVED":
                return func(*args, **kwargs)
            elif data.get("status") == "ACTIVE_DISAMBIGUATION_REQUIRED":
                raise ValueError(f"Ambiguity Halt: {data.get('prompt_to_user')}")
            else:
                raise PermissionError(f"Deterministic Halt: {data.get('action')}")
        return wrapper
