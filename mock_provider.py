"""Local Stripe-like provider simulator for gateway integration exercises."""

import asyncio
import os
import uuid
from decimal import Decimal
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field


def _latency_seconds() -> float:
    raw_value = os.getenv("MOCK_PROVIDER_LATENCY_SECONDS", "0")
    try:
        latency = float(raw_value)
    except ValueError as exc:
        raise RuntimeError(
            "MOCK_PROVIDER_LATENCY_SECONDS must be a number between 0 and 120."
        ) from exc
    if not 0 <= latency <= 120:
        raise RuntimeError(
            "MOCK_PROVIDER_LATENCY_SECONDS must be between 0 and 120."
        )
    return latency


def _drop_enabled() -> bool:
    raw_value = os.getenv("MOCK_PROVIDER_DROP_AFTER_ACCEPT", "false").lower()
    if raw_value not in {"true", "false", "1", "0", "yes", "no"}:
        raise RuntimeError(
            "MOCK_PROVIDER_DROP_AFTER_ACCEPT must be a boolean value."
        )
    return raw_value in {"true", "1", "yes"}


app = FastAPI(
    title="Zero-Data Mock Financial Provider",
    version="0.1.0",
    description="Local Stripe-like transfer endpoint for gateway testing.",
)
_transfers: dict[str, dict[str, Any]] = {}
_transfer_lock = asyncio.Lock()


class TransferRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    amount: Decimal = Field(gt=0)
    currency: str = Field(min_length=3, max_length=3, pattern=r"^[A-Za-z]{3}$")
    recipient: str = Field(min_length=1, max_length=200)
    idempotency_key: str = Field(min_length=1, max_length=255)


async def _withhold_response() -> Any:
    await asyncio.Event().wait()
    yield b""


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "provider": "mock"}


@app.post("/v1/transfers")
async def create_transfer(
    transfer: TransferRequest,
    idempotency_header: str | None = Header(default=None, alias="Idempotency-Key"),
    drop_after_accept: bool | None = Query(default=None),
) -> Any:
    if (
        idempotency_header is not None
        and idempotency_header != transfer.idempotency_key
    ):
        raise HTTPException(
            status_code=400,
            detail="Idempotency-Key header must match the request body.",
        )

    if latency := _latency_seconds():
        await asyncio.sleep(latency)

    payload = transfer.model_dump(mode="json")
    payload["currency"] = transfer.currency.upper()
    async with _transfer_lock:
        existing = _transfers.get(transfer.idempotency_key)
        if existing is not None:
            if existing["payload"] != payload:
                raise HTTPException(
                    status_code=409,
                    detail="Idempotency key was reused with a different payload.",
                )
            confirmation = {**existing["confirmation"], "cached": True}
        else:
            confirmation = {
                "id": f"tr_{uuid.uuid4().hex}",
                "object": "transfer",
                "amount": str(transfer.amount),
                "currency": transfer.currency.upper(),
                "recipient": transfer.recipient,
                "idempotency_key": transfer.idempotency_key,
                "status": "succeeded",
                "cached": False,
            }
            _transfers[transfer.idempotency_key] = {
                "payload": payload,
                "confirmation": confirmation,
            }

    should_drop = (
        _drop_enabled() if drop_after_accept is None else drop_after_accept
    )
    if should_drop:
        return StreamingResponse(
            _withhold_response(),
            media_type="application/json",
            headers={"X-Mock-Provider-Status": "accepted-response-withheld"},
        )
    return confirmation


@app.get("/v1/transfers/{idempotency_key}")
async def get_transfer_status(idempotency_key: str) -> dict[str, Any]:
    async with _transfer_lock:
        existing = _transfers.get(idempotency_key)
        if existing is None:
            raise HTTPException(status_code=404, detail="Transfer not found.")
        return {**existing["confirmation"], "cached": True}
