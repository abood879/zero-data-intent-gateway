import yaml
from pathlib import Path
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, ConfigDict
from app.engine import evaluate_governance

app = FastAPI(
    title="Zero-Data Intent Governance Gateway",
    version="3.0.0",
    description="Sub-millisecond Deterministic AI Governance with Active Disambiguation and Chained Cryptographic Audit."
)

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "policies.yaml"

def load_policies():
    if not CONFIG_PATH.exists():
        return {
            "approved_vendors": {
                "AWS": ["aws", "amazon", "aws_cloud_global"],
                "Microsoft": ["azure", "microsoft", "azure_enterprise"],
                "SAP": ["sap", "sap_ariba"],
                "Oracle": ["oracle", "oracle_cloud"]
            },
            "allowed_departments": ["Engineering", "Infrastructure", "Security"],
            "max_auto_approval_limit": 5000.0
        }
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

# مخطط صارم يمنع التخمين وحقن الحقول الغريبة
class StrictTransactionPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    id: str = Field(..., min_length=3, max_length=64, description="Unique transaction trace ID")
    amount: float = Field(..., gt=0.0, description="Exact transaction financial value")
    vendor: str = Field(..., min_length=2, description="Target vendor identifier")
    department: str = Field(..., min_length=2, description="Originating corporate department")
    budget_cleared: bool = Field(..., description="Explicit signoff verification")

@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "ACTIVE",
        "version": "3.0.0",
        "framework": "Zero-Data Intent Architecture",
        "security_features": [
            "Strict Constrained Schema",
            "Active Disambiguation Protocol",
            "Immutable Cryptographic Hash Chaining"
        ]
    }

@app.post("/v1/governance/evaluate", tags=["Governance"])
def evaluate_transaction(payload: StrictTransactionPayload):
    try:
        # قراءة السياسات ديناميكياً لضمان التطابق اللحظي
        current_policies = load_policies()
        return evaluate_governance(payload.model_dump(), current_policies)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
