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
GATEWAY_API_TOKEN = os.getenv("GATEWAY_API_TOKEN", "prod-deterministic-token-310")
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

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    if not hmac.compare_digest(credentials.credentials, GATEWAY_API_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid gateway token")
    return credentials.credentials

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

@app.post("/v1/evaluate", dependencies=[Depends(verify_token)])
def evaluate_transaction(req: GovernanceRequest):
    started_at = time.perf_counter()
    payload = req.model_dump()
    dof, violations = evaluate_dof(payload)
    status = "DENIED" if dof >= 2 else ("DISAMBIGUATION" if dof == 1 else "APPROVED")
    observe_transaction(status, dof, started_at)
    return {
        "status": status,
        "dof": dof,
        "violations": violations,
        "timestamp": time.time(),
    }

@app.post("/v1/governance/evaluate", dependencies=[Depends(verify_token)])
def evaluate_legacy_transaction(request: LegacyGovernanceRequest):
    started_at = time.perf_counter()
    legacy_payload = request.model_dump()
    known_vendor = request.vendor == "AWS_Cloud_Global"
    context = {
        "role": "finance_agent" if known_vendor else "guest",
        "max_limit": request.amount if request.budget_cleared else 1000,
    }
    dof, violations = governance_engine.evaluate(
        {
            "tool": "wire_transfer",
            "parameters": {"amount": request.amount},
            "context": context,
        }
    )[:2]
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
