import os
import yaml
import time
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, ConfigDict
from typing import Dict, Any
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from app.engine import evaluate_governance

app = FastAPI(
    title="Zero-Data Intent Governance Gateway",
    version="3.0.0",
    description="Sub-millisecond Deterministic AI Governance with Active Disambiguation, Chained Cryptographic Audit, and Real-time Prometheus Observability."
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

@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "ACTIVE",
        "version": "3.0.0",
        "framework": "Zero-Data Intent Architecture",
        "security_features": [
            "Strict Constrained Schema",
            "Active Disambiguation Protocol",
            "Immutable Cryptographic Hash Chaining",
            "Prometheus Enterprise Observability"
        ]
    }

@app.get("/metrics", tags=["Observability"])
def get_metrics():
    """تصدير مقاييس النظام المباشرة إلى Prometheus / Grafana"""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/v1/governance/evaluate", tags=["Governance"])
def evaluate_transaction(payload: StrictTransactionPayload):
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Engine Failure: {str(e)}")