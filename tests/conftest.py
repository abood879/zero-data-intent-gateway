import os
import tempfile

os.environ.setdefault("GATEWAY_API_TOKEN", "test-gateway-token")
os.environ.setdefault(
    "AUDIT_LEDGER_PATH",
    os.path.join(
        tempfile.gettempdir(),
        f"zero-data-gateway-tests-{os.getpid()}.jsonl",
    ),
)
os.environ.setdefault(
    "STEP_UP_NONCE_DB_PATH",
    os.path.join(
        tempfile.gettempdir(),
        f"zero-data-gateway-nonces-{os.getpid()}.sqlite3",
    ),
)
os.environ.setdefault(
    "GATEWAY_BUDGET_DB_PATH",
    os.path.join(
        tempfile.gettempdir(),
        f"zero-data-gateway-budgets-{os.getpid()}.sqlite3",
    ),
)
os.environ.pop("REDIS_URL", None)
