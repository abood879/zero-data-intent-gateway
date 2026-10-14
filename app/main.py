import hmac
import hashlib
import json
import os
import threading
import time
from fastapi import Depends, FastAPI, HTTPException, Response, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, ConfigDict, Field
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from typing import Any, Dict
from app.engine import governance_engine

app = FastAPI(
    title="Zero-Data Intent Governance Gateway",
    version="3.1.0",
    docs_url="/docs",
    redoc_url=None
)

security = HTTPBearer()
def load_token_identity_map() -> dict[str, dict[str, str]]:
    raw_mapping = os.getenv("TOKEN_IDENTITY_MAP")
    if not raw_mapping:
        return {}
    try:
        mapping = json.loads(raw_mapping)
    except json.JSONDecodeError as exc:
        raise RuntimeError("TOKEN_IDENTITY_MAP must contain valid JSON.") from exc
    if not isinstance(mapping, dict):
        raise RuntimeError("TOKEN_IDENTITY_MAP must be a JSON object.")
    return mapping


TOKEN_IDENTITY_MAP = load_token_identity_map()
TRANSACTIONS_TOTAL = Counter(
    "governance_transactions_total",
    "Total governance evaluations processed",
    ["status", "dof", "engine_source"],
)
LATENCY_HISTOGRAM = Histogram(
    "governance_latency_seconds",
    "Time spent evaluating governance requests",
)
_legacy_audit_lock = threading.Lock()
_legacy_audit_hash = "GENESIS_ZERO_DATA"

def verify_token_identity(
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> dict[str, str]:
    if not TOKEN_IDENTITY_MAP:
        raise HTTPException(
            status_code=503,
            detail="Token identity mapping is not configured.",
        )
    matched_identity = None
    for token, identity in TOKEN_IDENTITY_MAP.items():
        if isinstance(token, str) and hmac.compare_digest(
            credentials.credentials, token
        ):
            matched_identity = identity
    if matched_identity is None:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid gateway token")
    if (
        not isinstance(matched_identity, dict)
        or not isinstance(matched_identity.get("role"), str)
        or not isinstance(matched_identity.get("user_id"), str)
    ):
        raise HTTPException(
            status_code=503,
            detail="Token identity mapping contains an invalid identity.",
        )
    return {
        "role": matched_identity["role"],
        "user_id": matched_identity["user_id"],
    }

class GovernanceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    context: Dict[str, Any] = Field(default_factory=dict)

class LegacyGovernanceRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    id: str
    amount: float
    vendor: str
    department: str
    budget_cleared: bool

def evaluate_dof(payload: dict) -> tuple[int, list[str]]:
    dof, violations, _ = governance_engine.evaluate(payload)
    return dof, violations

def record_legacy_audit(payload: dict, status: str) -> str:
    global _legacy_audit_hash
    with _legacy_audit_lock:
        record = {
            "previous_hash": _legacy_audit_hash,
            "payload": payload,
            "status": status,
            "timestamp": time.time(),
        }
        encoded_record = json.dumps(record, sort_keys=True, separators=(",", ":"))
        _legacy_audit_hash = hashlib.sha256(encoded_record.encode("utf-8")).hexdigest()
        return _legacy_audit_hash

def observe_transaction(status: str, dof: int, started_at: float) -> None:
    LATENCY_HISTOGRAM.observe(time.perf_counter() - started_at)
    TRANSACTIONS_TOTAL.labels(
        status=status,
        dof=str(dof),
        engine_source="UnifiedGovernanceEngine",
    ).inc()

@app.get("/health")
def health():
    return {
        "status": "ACTIVE",
        "version": "3.1.0",
        "engine": "Deterministic-Kernel",
        "health": "healthy",
        "security_features": [
            "Fail-Closed Architecture",
            "Tamper-Evident SHA-256 Hash Chaining",
            "Contextual Execution Firewall"
        ]
    }

@app.get("/metrics")
def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/evaluate")
@app.post("/v1/evaluate")
def evaluate_transaction(
    req: GovernanceRequest,
    identity: dict[str, str] = Depends(verify_token_identity),
):
    started_at = time.perf_counter()
    payload = req.model_dump()
    client_context = payload.get("context", {})
    trusted_context = {
        key: value
        for key, value in client_context.items()
        if key not in {"role", "user_id", "max_limit", "__signature__"}
    }
    trusted_context.update(identity)
    payload["context"] = trusted_context
    dof, violations = evaluate_dof(payload)
    status = "DENIED" if dof >= 2 else ("DISAMBIGUATION" if dof == 1 else "APPROVED")
    observe_transaction(status, dof, started_at)
    return {
        "status": status,
        "dof": dof,
        "violations": violations,
        "timestamp": time.time(),
    }

@app.post("/v1/governance/evaluate")
def evaluate_legacy_transaction(
    request: LegacyGovernanceRequest,
    identity: dict[str, str] = Depends(verify_token_identity),
):
    started_at = time.perf_counter()
    legacy_payload = request.model_dump()
    context = {
        **identity,
    }
    dof, violations = governance_engine.evaluate(
        {
            "tool": "wire_transfer",
            "parameters": {"amount": request.amount},
            "context": context,
        }
    )[:2]
    if not request.budget_cleared and dof == 0:
        dof = 1
        violations = ["Budget approval is required before execution."]
    if dof == 0:
        status = "INTENT_LOCKED"
    elif dof == 1:
        status = "ACTIVE_DISAMBIGUATION_REQUIRED"
    else:
        status = "HALTED_ARRESTING_HAZARD"

    audit_hash = record_legacy_audit(legacy_payload, status)
    observe_transaction(status, dof, started_at)
    result = {
        "status": status,
        "degrees_of_freedom": dof,
        "tokens_consumed": 0,
        "violations": violations,
        "audit_hash": audit_hash,
    }
    if dof == 1:
        result["required_field"] = "budget_cleared"
    return result
