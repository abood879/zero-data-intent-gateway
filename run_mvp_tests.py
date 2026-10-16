"""Run local MVP security-invariant checks through agent.py and mock_provider.py."""

import contextlib
import io
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from unittest.mock import patch

from fastapi.testclient import TestClient


GREEN = "\033[92m"
RESET = "\033[0m"


def _configure_isolated_state(state_dir: str) -> None:
    state_path = Path(state_dir)
    os.environ.update(
        {
            "AUDIT_LEDGER_PATH": str(state_path / "audit_ledger.jsonl"),
            "GATEWAY_AGENT_ID": "mvp-security-test-agent",
            "GATEWAY_AGENT_ROLE": "finance_operator",
            "GATEWAY_AGENT_USER_ID": "mvp-security-test-user",
            "GATEWAY_BUDGET_DB_PATH": str(state_path / "budgets.sqlite3"),
            "GATEWAY_CONTEXT_HMAC_SECRET": "mvp-test-only-context-secret",
            "GATEWAY_WORKFLOW_ID": "mvp-security-test-workflow",
            "MOCK_PROVIDER_URL": "http://mock-provider.test",
            "STEP_UP_NONCE_DB_PATH": str(state_path / "step_up_nonces.sqlite3"),
        }
    )
    os.environ.pop("REDIS_URL", None)


def _load_components() -> tuple[Any, Any, TestClient]:
    import agent
    import mock_provider

    mock_provider._transfers.clear()
    return agent, mock_provider, TestClient(mock_provider.app)


def _run_scenarios(agent: Any, provider_client: TestClient) -> tuple[bool, bool]:
    outbound_posts = 0

    class ProviderHttpClient:
        def __init__(self, *, timeout: float):
            self.timeout = timeout

        def __enter__(self) -> "ProviderHttpClient":
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def post(
            self,
            url: str,
            *,
            headers: dict[str, str],
            json: dict[str, Any],
            params: dict[str, str] | None = None,
        ) -> Any:
            nonlocal outbound_posts
            outbound_posts += 1
            return provider_client.post(
                urlsplit(url).path,
                headers=headers,
                json=json,
                params=params,
            )

    def invoke_agent(amount: str) -> tuple[int | None, str, str, Exception | None]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        try:
            with (
                patch.object(agent.httpx, "Client", ProviderHttpClient),
                patch.object(sys, "argv", ["agent.py", "--amount", amount]),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                return_code = agent.main()
            return return_code, stdout.getvalue(), stderr.getvalue(), None
        except Exception as exc:
            return None, stdout.getvalue(), stderr.getvalue(), exc

    strict_policy_passed = False
    before_rejected_transfer = outbound_posts
    try:
        return_code, _, error_output, error = invoke_agent("6000.00")
        assert error is not None or return_code != 0, (
            "The $6,000 transaction unexpectedly succeeded."
        )
        rejection_detail = f"{error or ''} {error_output}".lower()
        assert any(
            phrase in rejection_detail
            for phrase in ("policy", "budget", "blocked", "limit", "dof")
        ), f"Rejection did not report a policy/budget error: {rejection_detail!r}"
        assert outbound_posts == before_rejected_transfer, (
            "The rejected transaction attempted an HTTP provider call."
        )
        strict_policy_passed = True
    except Exception as exc:
        print(f"Strict Policy Enforcement: FAIL — {exc}", file=sys.stderr)

    double_spend_passed = False
    before_valid_transfer = outbound_posts
    try:
        first_code, first_output, first_error, first_exception = invoke_agent(
            "500.00"
        )
        assert first_exception is None and first_code == 0, (
            f"The valid $500 transaction failed: "
            f"{first_exception or first_error or first_output}"
        )
        first_confirmation = json.loads(first_output)
        assert first_confirmation.get("status") == "succeeded", (
            f"Provider did not confirm success: {first_confirmation!r}"
        )
        assert outbound_posts == before_valid_transfer + 1, (
            "The initial valid transaction did not make exactly one provider call."
        )

        second_code, second_output, second_error, second_exception = invoke_agent(
            "500.00"
        )
        assert second_exception is None and second_code == 0, (
            f"The duplicate transaction did not return normally: "
            f"{second_exception or second_error or second_output}"
        )
        second_confirmation = json.loads(second_output)
        assert (
            second_confirmation.get("status") == "COMMITTED"
            and second_confirmation.get("cached") is True
            and second_confirmation.get("idempotency_key")
            == first_confirmation.get("idempotency_key")
        ), f"The duplicate did not return the original idempotency cache: {second_confirmation!r}"
        assert outbound_posts == before_valid_transfer + 1, (
            "The duplicate transaction made a second provider call."
        )
        double_spend_passed = True
    except Exception as exc:
        print(f"Double-Spend Prevention: FAIL — {exc}", file=sys.stderr)

    if strict_policy_passed:
        print(f"{GREEN}✅ Strict Policy Enforcement: PASS{RESET}")
    if double_spend_passed:
        print(f"{GREEN}✅ Double-Spend Prevention: PASS{RESET}")
    return strict_policy_passed, double_spend_passed


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="zero-data-mvp-tests-") as state_dir:
        _configure_isolated_state(state_dir)
        try:
            agent, _, provider_client = _load_components()
            try:
                strict_policy_passed, double_spend_passed = _run_scenarios(
                    agent, provider_client
                )
            finally:
                provider_client.close()
        except Exception as exc:
            print(f"MVP test setup failed: {exc}", file=sys.stderr)
            return 1

    return 0 if strict_policy_passed and double_spend_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
