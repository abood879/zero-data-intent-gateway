import asyncio
import json
import shutil
from decimal import Decimal

import httpx
import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException
from redis.exceptions import RedisError

from app import main as gateway_main
from app.engine import UnifiedGovernanceEngine


@pytest.fixture
def proxy_client(monkeypatch, tmp_path):
    monkeypatch.setattr(
        gateway_main,
        "TOKEN_IDENTITY_MAP",
        {
            "proxy-test-token": {
                "role": "finance_agent",
                "user_id": "proxy-test-user",
            }
        },
    )
    monkeypatch.setattr(
        gateway_main,
        "governance_engine",
        UnifiedGovernanceEngine(tmp_path / "proxy-budget.sqlite3"),
    )
    monkeypatch.setenv("MOCK_PROVIDER_URL", "http://mock-provider.test")
    return TestClient(gateway_main.app)


def _headers(idempotency_key: str) -> dict[str, str]:
    return {
        "Authorization": "Bearer proxy-test-token",
        "Idempotency-Key": idempotency_key,
    }


def _patch_provider(monkeypatch, handler):
    real_async_client = httpx.AsyncClient

    class MockAsyncClient:
        def __init__(self, *, timeout):
            self.client = real_async_client(
                transport=httpx.MockTransport(handler),
                timeout=timeout,
            )

        async def __aenter__(self):
            return await self.client.__aenter__()

        async def __aexit__(self, *args):
            return await self.client.__aexit__(*args)

    monkeypatch.setattr(gateway_main.httpx, "AsyncClient", MockAsyncClient)


def test_proxy_rejects_policy_violation_before_provider_call(
    proxy_client, monkeypatch
):
    provider_calls = []

    def provider_handler(request):
        provider_calls.append(request)
        return httpx.Response(200, json={"status": "succeeded"})

    _patch_provider(monkeypatch, provider_handler)
    key = "proxy-over-limit-6000"
    response = proxy_client.post(
        "/v1/proxy/transfers",
        headers=_headers(key),
        json={
            "amount": "6000.00",
            "currency": "USD",
            "recipient": "account-1",
            "idempotency_key": key,
        },
    )

    assert response.status_code == 403
    assert "policy" in response.json()["detail"]["error"].lower()
    assert provider_calls == []


def test_proxy_commits_once_and_returns_cached_duplicate(
    proxy_client, monkeypatch
):
    provider_calls = []

    def provider_handler(request):
        provider_calls.append(request)
        return httpx.Response(
            200,
            json={
                "status": "succeeded",
                "idempotency_key": request.headers["Idempotency-Key"],
            },
        )

    _patch_provider(monkeypatch, provider_handler)
    key = "proxy-valid-500-once"
    payload = {
        "amount": "500.00",
        "currency": "USD",
        "recipient": "account-1",
        "idempotency_key": key,
    }

    first_response = proxy_client.post(
        "/v1/proxy/transfers",
        headers=_headers(key),
        json=payload,
    )
    duplicate_response = proxy_client.post(
        "/v1/proxy/transfers",
        headers=_headers(key),
        json=payload,
    )

    assert first_response.status_code == 200
    assert first_response.json()["status"] == "succeeded"
    assert duplicate_response.status_code == 200
    assert duplicate_response.json()["status"] == "COMMITTED"
    assert duplicate_response.json()["cached"] is True
    assert len(provider_calls) == 1
    assert provider_calls[0].url.path == "/v1/transfers"
    assert json.loads(provider_calls[0].content) == payload


def test_proxy_rejects_cumulative_budget_excess_before_provider_call(
    proxy_client, monkeypatch
):
    provider_calls = []

    def provider_handler(request):
        provider_calls.append(request)
        return httpx.Response(200, json={"status": "succeeded"})

    _patch_provider(monkeypatch, provider_handler)
    gateway_main.governance_engine.role_currency_budget_limits["finance_agent"][
        "USD"
    ] = Decimal("500.00")

    accepted_key = "proxy-budget-accepted"
    accepted_response = proxy_client.post(
        "/v1/proxy/transfers",
        headers=_headers(accepted_key),
        json={
            "amount": "500.00",
            "currency": "USD",
            "recipient": "account-1",
            "idempotency_key": accepted_key,
        },
    )
    denied_key = "proxy-budget-denied"
    denied_response = proxy_client.post(
        "/v1/proxy/transfers",
        headers=_headers(denied_key),
        json={
            "amount": "1.00",
            "currency": "USD",
            "recipient": "account-1",
            "idempotency_key": denied_key,
        },
    )

    assert accepted_response.status_code == 200
    assert denied_response.status_code == 403
    assert "budget" in denied_response.json()["detail"].lower()
    assert len(provider_calls) == 1


def test_proxy_uses_redis_lock_when_configured(proxy_client, monkeypatch):
    calls = []

    class FakeLock:
        async def acquire(self):
            calls.append("acquire")
            return True

        async def release(self):
            calls.append("release")

    class FakeRedis:
        def lock(self, name, *, timeout, blocking_timeout):
            calls.append((name, timeout, blocking_timeout))
            return FakeLock()

        async def aclose(self):
            calls.append("close")

    monkeypatch.setenv("REDIS_URL", "redis://redis.test/0")
    monkeypatch.setattr(
        gateway_main.redis_async,
        "from_url",
        lambda url, *, decode_responses: FakeRedis(),
    )

    async def use_lock():
        async with gateway_main._idempotency_lock("test-idempotency-key"):
            calls.append("inside")

    asyncio.run(use_lock())

    assert calls[1:] == ["acquire", "inside", "release", "close"]
    assert calls[0][0].startswith("gateway:idempotency:")
    assert calls[0][1:] == (60, 15)


def test_proxy_fails_closed_when_redis_lock_is_unavailable(
    proxy_client, monkeypatch
):
    class FakeLock:
        async def acquire(self):
            raise RedisError("Redis is unavailable")

    class FakeRedis:
        def lock(self, *_args, **_kwargs):
            return FakeLock()

        async def aclose(self):
            return None

    monkeypatch.setenv("REDIS_URL", "redis://redis.test/0")
    monkeypatch.setattr(
        gateway_main.redis_async,
        "from_url",
        lambda *_args, **_kwargs: FakeRedis(),
    )

    async def use_lock():
        async with gateway_main._idempotency_lock("unavailable-key"):
            pytest.fail("The gateway must not enter the provider path without Redis.")

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(use_lock())
    assert exc_info.value.status_code == 503


def test_admin_can_reload_gateway_policy_file(proxy_client, monkeypatch, tmp_path):
    policy_path = tmp_path / "policies.yaml"
    shutil.copyfile(
        gateway_main.governance_engine.policy_file_path,
        policy_path,
    )
    monkeypatch.setattr(
        gateway_main.governance_engine,
        "policy_file_path",
        policy_path,
    )
    monkeypatch.setattr(
        gateway_main,
        "TOKEN_IDENTITY_MAP",
        {
            "proxy-test-token": {
                "role": "finance_agent",
                "user_id": "proxy-test-user",
            },
            "admin-test-token": {
                "role": "admin",
                "user_id": "policy-admin",
            },
        },
    )
    original = policy_path.read_text()
    policy_path.write_text(
        original.replace('USD: "5000"', 'USD: "4000"', 1),
        encoding="utf-8",
    )

    response = proxy_client.post(
        "/v1/admin/reload-policies",
        headers={"Authorization": "Bearer admin-test-token"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "reloaded"
    assert gateway_main.governance_engine.critical_financial_limits["USD"] == Decimal(
        "4000"
    )
    assert response.json()["policy_revision"] == gateway_main.governance_engine.policy_revision


def test_policy_reload_requires_admin_role(proxy_client):
    response = proxy_client.post(
        "/v1/admin/reload-policies",
        headers={"Authorization": "Bearer proxy-test-token"},
    )
    assert response.status_code == 403
