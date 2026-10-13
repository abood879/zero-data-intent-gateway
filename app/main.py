from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from app.engine import PolicyManager, DeterministicGate

app = FastAPI(title="Zero-Data Intent Governance Gateway", version="2.0.0", description="Sub-millisecond Deterministic AI Governance Middleware for Enterprise Operations.")
policy = PolicyManager()
gate = DeterministicGate(policy)

class TransactionPayload(BaseModel):
    id: Optional[str] = None
    amount: float
    vendor: str
    department: str
    budget_cleared: bool

@app.get("/health")
def health_check(): return {"status": "ACTIVE", "framework": "Zero-Data Intent Architecture"}

@app.post("/v1/governance/evaluate")
def evaluate_transaction(payload: TransactionPayload):
    try: return gate.evaluate(payload.model_dump())
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))
