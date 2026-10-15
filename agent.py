"""Small SDK-mediated transfer demo against the local mock provider."""

import argparse
import hashlib
import json
import os
import sys
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx

import app.main as gateway_main
from sdk import (
    CriticalAuditFailureError,
    GatewaySecurityError,
    SecureProviderTransport,
    protected_tool,
)


def _positive_amount(value: str) -> str:
    try:
        amount = Decimal(value)
    except InvalidOperation as exc:
        raise argparse.ArgumentTypeError("amount must be a decimal number") from exc
    if not amount.is_finite() or amount <= 0:
        raise argparse.ArgumentTypeError("amount must be greater than zero")
    return format(amount, "f")


def _idempotency_key(
    amount: str, currency: str, recipient: str, agent_id: str, workflow_id: str
) -> str:
    canonical_payload = json.dumps(
        {
            "agent_id": agent_id,
            "amount": amount,
            "currency": currency.upper(),
            "recipient": recipient,
            "workflow_id": workflow_id,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return f"demo_{hashlib.sha256(canonical_payload).hexdigest()}"


def _signed_context(role: str, user_id: str) -> dict[str, str]:
    try:
        return gateway_main._issue_trusted_context(
            {"role": role, "user_id": user_id}
        )
    except RuntimeError as exc:
        raise RuntimeError(
            "Set GATEWAY_CONTEXT_HMAC_SECRET for this local SDK demo."
        ) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Submit a demo transfer through the Zero-Data Gateway SDK."
    )
    parser.add_argument("--amount", type=_positive_amount, default="500.00")
    parser.add_argument("--currency", default="USD")
    parser.add_argument("--recipient", default="account_x")
    parser.add_argument(
        "--drop-after-accept",
        action="store_true",
        help="Ask the mock provider to accept the transfer but withhold its response.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    currency = args.currency.strip().upper()
    if len(currency) != 3 or not currency.isalpha():
        print("Currency must be a three-letter code.", file=sys.stderr)
        return 2

    agent_id = os.getenv("GATEWAY_AGENT_ID", "demo-agent")
    workflow_id = os.getenv("GATEWAY_WORKFLOW_ID", "demo-transfer")
    role = os.getenv("GATEWAY_AGENT_ROLE", "finance_agent")
    user_id = os.getenv("GATEWAY_AGENT_USER_ID", agent_id)
    idempotency_key = _idempotency_key(
        args.amount, currency, args.recipient, agent_id, workflow_id
    )
    provider_url = os.getenv(
        "MOCK_PROVIDER_URL", "http://127.0.0.1:8090"
    ).rstrip("/")
    try:
        timeout_seconds = float(os.getenv("AGENT_PROVIDER_TIMEOUT_SECONDS", "5"))
    except ValueError:
        print("AGENT_PROVIDER_TIMEOUT_SECONDS must be a number.", file=sys.stderr)
        return 2
    if timeout_seconds <= 0:
        print("AGENT_PROVIDER_TIMEOUT_SECONDS must be positive.", file=sys.stderr)
        return 2

    def send_to_provider(
        *, headers: dict[str, str], payload: dict[str, Any], **_: Any
    ) -> dict[str, Any]:
        with httpx.Client(timeout=timeout_seconds) as client:
            response = client.post(
                f"{provider_url}/v1/transfers",
                headers=headers,
                json=payload,
                params={"drop_after_accept": "true"}
                if args.drop_after_accept
                else None,
            )
            response.raise_for_status()
            return response.json()

    transport = SecureProviderTransport(send_to_provider)

    @protected_tool(tool_name="wire_transfer")
    def transfer(
        amount: str,
        currency: str,
        recipient: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return transport.dispatch(
            idempotency_key=idempotency_key,
            payload={
                "amount": amount,
                "currency": currency,
                "recipient": recipient,
                "idempotency_key": idempotency_key,
            },
        )

    try:
        result = transfer(
            amount=args.amount,
            currency=currency,
            recipient=args.recipient,
            idempotency_key=idempotency_key,
            __context__=_signed_context(role, user_id),
        )
    except CriticalAuditFailureError as exc:
        print(
            f"Gateway requires reconciliation: {exc}",
            file=sys.stderr,
        )
        return 3
    except httpx.HTTPError as exc:
        print(
            "Provider communication failed after dispatch may have started; "
            "treat the outcome as unknown and reconcile before retrying. "
            f"Details: {exc}",
            file=sys.stderr,
        )
        return 3
    except (GatewaySecurityError, RuntimeError) as exc:
        print(f"Transfer did not complete normally: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
