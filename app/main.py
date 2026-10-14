import os
import hmac
import yaml
import time
from contextlib import asynccontextmanager

def evaluate_dof(payload: dict) -> tuple[int, list[str]]:
    dof = 0
    reasons = []
    
    # 1. Structural / Schema Check
    tool = payload.get("tool")
    params = payload.get("parameters", {})
    context = payload.get("context", {})
    
    if not tool:
        dof += 2
        reasons.append("Missing target tool definition")
        return dof, reasons

    # 2. RBAC Policy Check
    caller_role = context.get("role", "guest")
    restricted_tools = {
        "admin_execute": ["admin"],
        "database_drop": ["superadmin"],
        "wire_transfer": ["finance_agent", "admin"]
    }
    
    if tool in restricted_tools and caller_role not in restricted_tools[tool]:
        dof += 2
        reasons.append(f"Role '{caller_role}' unauthorized for tool '{tool}'")
        return dof, reasons

    # 3. Contextual / Financial Threshold Check
    if tool == "wire_transfer":
        amount = params.get("amount", 0)
        max_limit = context.get("max_limit", 1000)
        
        if not isinstance(amount, (int, float)) or amount <= 0:
            dof += 2
            reasons.append("Invalid transfer amount")
        elif amount > 10000:
            # تجاوز السقف الحرج للمؤسسة -> Hard Halt
            dof += 2
            reasons.append(f"Amount {amount} exceeds critical threshold (10,000)")
        elif amount > max_limit:
            # يحتاج تأكيد بشري Step-up / HITL -> DoF = 1
            dof += 1
            reasons.append(f"Amount {amount} exceeds role limit {max_limit}; requires Human-In-The-Loop approval")

    return dof, reasons

from fastapi import Depends, FastAPI, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict
from typing import Dict, Any
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from app.engine import AuditLedgerUnavailable, PolicyEngineUnavailable, evaluate_governance


@asynccontextmanager
async def lifespan(_: FastAPI):
    if not os.getenv("GATEWAY_API_TOKEN"):
        raise RuntimeError("CRITICAL STARTUP FAILURE: GATEWAY_API_TOKEN is mandatory.")
    yield


app = FastAPI(
    title="Zero-Data Intent Governance Gateway",
    version="3.1.0",
    description="Sub-millisecond Deterministic AI Governance with Active Disambiguation, Chained Cryptographic Audit, and Real-time Prometheus Observability.",
    lifespan=lifespan,
)

# --- مقاييس المراقبة المؤسسية (Prometheus Metrics) ---
TRANSACTIONS_TOTAL = Counter(
    "governance_transactions_total",
    "Total evaluation requests processed by the gateway",
    ["status", "dof", "engine_source"]
)

LATENCY_HISTOGRAM = Histogram(
    "governance_latency_seconds",
    "Time spent evaluating transactions in seconds",
    buckets=[0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1]
)

# 1. سياسة التحقق الصارم من المدخلات (Strict Schemas)
class StrictTransactionPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    id: str
    amount: float
    vendor: str
    department: str
    budget_cleared: bool

def load_policies() -> Dict[str, Any]:
    policy_path = os.path.join(os.path.dirname(__file__), "..", "config", "policies.yaml")
    if os.path.exists(policy_path):
        with open(policy_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {}

POLICIES = load_policies()


def verify_gateway_token(authorization: str | None = Header(default=None)) -> None:
    expected_token = os.getenv("GATEWAY_API_TOKEN")
    if not expected_token:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized or Missing Gateway Token",
        )
    supplied_token = (authorization or "").encode("utf-8")
    expected_authorization = f"Bearer {expected_token}".encode("utf-8")
    if not hmac.compare_digest(supplied_token, expected_authorization):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized or Missing Gateway Token",
        )


@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "ACTIVE",
        "version": "3.1.0",
        "framework": "Zero-Data Intent Architecture",
        "security_features": [
            "Strict Constrained Schema",
            "Active Disambiguation Protocol",
            "Tamper-Evident SHA-256 Hash Chaining",
            "Prometheus Enterprise Observability"
        ]
    }

@app.get("/metrics", tags=["Observability"])
def get_metrics():
    """تصدير مقاييس النظام المباشرة إلى Prometheus / Grafana"""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/v1/governance/evaluate", tags=["Governance"])
def evaluate_transaction(
    payload: StrictTransactionPayload,
    _: None = Depends(verify_gateway_token),
):
    start = time.perf_counter()
    try:
        raw_dict = payload.model_dump()
        decision = evaluate_governance(raw_dict, POLICIES)
        
        # تسجيل القياسات
        duration = time.perf_counter() - start
        LATENCY_HISTOGRAM.observe(duration)
        TRANSACTIONS_TOTAL.labels(
            status=decision.get("status", "UNKNOWN"),
            dof=str(decision.get("degrees_of_freedom", 0)),
            engine_source=decision.get("engine_source", "Internal")
        ).inc()
        
        return decision
    except PolicyEngineUnavailable as e:
        raise HTTPException(status_code=503, detail="Policy engine unavailable; transaction denied") from e
    except AuditLedgerUnavailable as e:
        raise HTTPException(status_code=503, detail="Audit ledger unavailable; transaction denied") from e
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error; transaction denied")