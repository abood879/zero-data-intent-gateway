import asyncio
from contextlib import asynccontextmanager
import hmac
import hashlib
import json
import logging
import os
import secrets
import threading
import time
from decimal import Decimal, InvalidOperation
from typing import AsyncIterator
from fastapi import Depends, FastAPI, HTTPException, Request, Response, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
import httpx
from pydantic import BaseModel, ConfigDict, Field
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from typing import Any, Dict
import redis.asyncio as redis_async
from redis.exceptions import LockNotOwnedError, RedisError
from app.engine import (
    IdempotencyConflictError,
    UnsupportedCurrencyError,
    governance_engine,
)

logger = logging.getLogger(__name__)

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


def _context_hmac_secret() -> bytes:
    secret = os.getenv("GATEWAY_CONTEXT_HMAC_SECRET")
    if not secret:
        raise RuntimeError("GATEWAY_CONTEXT_HMAC_SECRET must be configured.")
    return secret.encode("utf-8")


def _issue_trusted_context(identity: dict[str, str]) -> dict[str, str]:
    signed_identity = dict(identity)
    canonical_identity = json.dumps(
        signed_identity,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    signed_identity["__signature__"] = hmac.new(
        _context_hmac_secret(), canonical_identity, hashlib.sha256
    ).hexdigest()
    return signed_identity


def _issue_step_up_approval_token(
    *,
    tool: str,
    parameters: dict,
    identity: dict[str, str],
    expires_at: float,
) -> dict[str, str | float]:
    params_digest = hashlib.sha256(
        json.dumps(
            parameters,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    claims: dict[str, str | float] = {
        "tool": tool,
        "params_digest": params_digest,
        "role": identity["role"],
        "user_id": identity["user_id"],
        "expires_at": expires_at,
        "nonce": secrets.token_urlsafe(24),
    }
    signature = hmac.new(
        _context_hmac_secret(),
        b"step-up-approval:v1:"
        + json.dumps(
            claims,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {**claims, "signature": signature}

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


@asynccontextmanager
async def _idempotency_lock(idempotency_key: str) -> AsyncIterator[None]:
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        yield
        return

    try:
        redis_client = redis_async.from_url(redis_url, decode_responses=True)
    except (RedisError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Idempotency lock service is unavailable.",
        ) from exc
    lock_name = (
        "gateway:idempotency:"
        + hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
    )
    lock = redis_client.lock(
        lock_name,
        timeout=60,
        blocking_timeout=15,
    )
    try:
        acquired = await lock.acquire()
    except RedisError as exc:
        await redis_client.aclose()
        raise HTTPException(
            status_code=503,
            detail="Idempotency lock service is unavailable.",
        ) from exc
    if not acquired:
        await redis_client.aclose()
        raise HTTPException(
            status_code=409,
            detail="A request with this idempotency key is already in progress.",
        )

    try:
        yield
    finally:
        try:
            await lock.release()
        except (LockNotOwnedError, RedisError) as exc:
            logger.exception("Could not release distributed idempotency lock.")
            raise HTTPException(
                status_code=503,
                detail="Idempotency lock could not be safely released.",
            ) from exc
        finally:
            await redis_client.aclose()


@app.post("/v1/proxy/transfers")
async def proxy_transfer(
    request: Request,
    identity: dict[str, str] = Depends(verify_token_identity),
) -> Response:
    started_at = time.perf_counter()
    raw_payload = await request.body()
    try:
        payload = json.loads(raw_payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=400,
            detail="Request body must be valid JSON.",
        ) from exc
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=400,
            detail="Transfer payload must be a JSON object.",
        )

    idempotency_key = request.headers.get("Idempotency-Key")
    payload_key = payload.get("idempotency_key")
    if (
        not isinstance(idempotency_key, str)
        or not idempotency_key.strip()
        or payload_key != idempotency_key
    ):
        raise HTTPException(
            status_code=400,
            detail="Idempotency-Key header must match the request payload.",
        )

    policy_parameters = {
        "amount": payload.get("amount"),
        "currency": payload.get("currency", "USD"),
    }
    dof, violations, _ = governance_engine.evaluate(
        {
            "tool": "wire_transfer",
            "parameters": policy_parameters,
            "context": identity,
        }
    )
    if dof != 0:
        observe_transaction("DENIED", dof, started_at)
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Transaction rejected by gateway policy.",
                "violations": violations,
            },
        )

    try:
        amount = Decimal(str(policy_parameters["amount"]))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=400,
            detail="Transaction amount is invalid.",
        ) from exc
    currency = policy_parameters["currency"]
    if not isinstance(currency, str) or not currency.strip():
        raise HTTPException(status_code=400, detail="Transaction currency is invalid.")

    try:
        canonical_payload = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=400,
            detail="Transfer payload is not valid JSON.",
        ) from exc
    payload_hash = hashlib.sha256(canonical_payload).hexdigest()
    async with _idempotency_lock(idempotency_key):
        try:
            (
                reserved,
                _,
                reservation_id,
                execution_token,
                cached_confirmation,
            ) = await asyncio.to_thread(
                governance_engine.reserve_budget_with_confirmation,
                identity["role"],
                identity["user_id"],
                amount,
                idempotency_key,
                currency,
                "wire_transfer",
                payload_hash,
            )
        except IdempotencyConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except UnsupportedCurrencyError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not reserved:
            raise HTTPException(
                status_code=403,
                detail="Cumulative financial budget exceeded for this identity and time window.",
            )
        if cached_confirmation is not None:
            observe_transaction("IDEMPOTENT_REPLAY", dof, started_at)
            return JSONResponse(content=cached_confirmation)
        if reservation_id is None or execution_token is None:
            raise HTTPException(
                status_code=503,
                detail="Gateway could not reserve the transaction.",
            )

        provider_url = os.getenv(
            "MOCK_PROVIDER_URL", "http://mock-provider:8090"
        ).rstrip("/")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                provider_response = await client.post(
                    f"{provider_url}/v1/transfers",
                    content=raw_payload,
                    headers={
                        "Content-Type": request.headers.get(
                            "content-type", "application/json"
                        ),
                        "Idempotency-Key": idempotency_key,
                    },
                )
        except httpx.RequestError as exc:
            await asyncio.to_thread(
                governance_engine.flag_for_reconciliation,
                reservation_id,
            )
            observe_transaction("PROVIDER_OUTCOME_UNCERTAIN", dof, started_at)
            raise HTTPException(
                status_code=502,
                detail="Provider outcome is uncertain; transaction requires reconciliation.",
            ) from exc

        if 200 <= provider_response.status_code < 300:
            try:
                await asyncio.to_thread(
                    governance_engine.commit_budget,
                    reservation_id,
                    execution_token,
                )
            except RuntimeError as exc:
                await asyncio.to_thread(
                    governance_engine.flag_for_reconciliation,
                    reservation_id,
                )
                observe_transaction("COMMIT_RECONCILIATION_REQUIRED", dof, started_at)
                raise HTTPException(
                    status_code=503,
                    detail="Provider accepted the transfer but gateway commit requires reconciliation.",
                ) from exc
            await asyncio.to_thread(
                governance_engine.mark_idempotency_status,
                idempotency_key,
                "COMMITTED",
            )
            observe_transaction("PROVIDER_SUCCEEDED", dof, started_at)
        elif 400 <= provider_response.status_code < 500 and provider_response.status_code not in {
            408,
            409,
            425,
            429,
        }:
            await asyncio.to_thread(
                governance_engine.release_budget,
                reservation_id,
            )
            await asyncio.to_thread(
                governance_engine.mark_idempotency_status,
                idempotency_key,
                "ABORTED",
            )
            observe_transaction("PROVIDER_REJECTED", dof, started_at)
        else:
            await asyncio.to_thread(
                governance_engine.flag_for_reconciliation,
                reservation_id,
            )
            observe_transaction("PROVIDER_OUTCOME_UNCERTAIN", dof, started_at)

        response_headers = {}
        content_type = provider_response.headers.get("content-type")
        if content_type:
            response_headers["content-type"] = content_type
        return Response(
            content=provider_response.content,
            status_code=provider_response.status_code,
            headers=response_headers,
        )


@app.post("/v1/admin/reload-policies")
async def reload_policies(
    identity: dict[str, str] = Depends(verify_token_identity),
) -> dict[str, str]:
    if identity["role"] not in {"admin", "governance_admin"}:
        raise HTTPException(
            status_code=403,
            detail="Only an administrator may reload gateway policies.",
        )
    try:
        revision = await asyncio.to_thread(governance_engine.reload_policies)
    except (OSError, RuntimeError, ValueError) as exc:
        logger.exception("Gateway policy reload failed.")
        raise HTTPException(
            status_code=503,
            detail="Gateway policies could not be reloaded.",
        ) from exc
    return {"status": "reloaded", "policy_revision": revision}


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
