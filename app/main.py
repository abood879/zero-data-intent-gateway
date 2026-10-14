import hmac
import hashlib
import os
import time
from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from app.engine import governance_engine

app = FastAPI(
    title="Zero-Data Intent Governance Gateway",
    version="3.1.0",
    docs_url="/docs",
    redoc_url=None
)

security = HTTPBearer()
GATEWAY_API_TOKEN = os.getenv("GATEWAY_API_TOKEN", "prod-deterministic-token-310")

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    if not hmac.compare_digest(credentials.credentials, GATEWAY_API_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid gateway token")
    return credentials.credentials

class GovernanceRequest(BaseModel):
    tool: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    context: Dict[str, Any] = Field(default_factory=dict)

def evaluate_dof(payload: dict) -> tuple[int, list[str]]:
    dof, violations, _ = governance_engine.evaluate(payload)
    return dof, violations

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "version": "3.1.0",
        "engine": "Deterministic-Kernel",
        "security_features": [
            "Fail-Closed Architecture",
            "Tamper-Evident SHA-256 Hash Chaining",
            "Contextual Execution Firewall"
        ]
    }

@app.post("/v1/evaluate")
def evaluate_transaction(req: GovernanceRequest, token: str = Depends(verify_token)):
    try:
        payload = req.model_dump()
        dof, violations = evaluate_dof(payload)
        
        status = "DENIED" if dof >= 2 else ("DISAMBIGUATION" if dof == 1 else "APPROVED")
        return {
            "status": status,
            "dof": dof,
            "violations": violations,
            "timestamp": time.time()
        }
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Internal server error; transaction denied"
        )
