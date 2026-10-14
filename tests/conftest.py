import os
import tempfile


os.environ.setdefault("GATEWAY_API_TOKEN", "test-gateway-token")
os.environ["AUDIT_LEDGER_PATH"] = os.path.join(
    tempfile.gettempdir(),
    f"zero-data-gateway-tests-{os.getpid()}.jsonl",
)