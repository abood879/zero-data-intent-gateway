import os
import json
import hashlib
import hmac
import logging
import math
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

logger = logging.getLogger(__name__)

ROLE_CURRENCY_TRANSACTION_LIMITS = {
    "finance_operator": {
        "USD": Decimal("5000"),
        "EUR": Decimal("4500"),
    },
    "finance_agent": {
        "USD": Decimal("10000"),
        "EUR": Decimal("9000"),
    },
    "admin": {
        "USD": Decimal("25000"),
        "EUR": Decimal("20000"),
    },
}
CRITICAL_FINANCIAL_LIMITS = {
    "USD": Decimal("5000"),
    "EUR": Decimal("4500"),
}


class BudgetStateConflictError(RuntimeError):
    """Raised when a reservation is no longer eligible for a state transition."""


class SecurityViolationError(PermissionError):
    """Raised when a privileged governance operation is not authorized."""


class ReconciliationProofRequiredError(BudgetStateConflictError):
    """Raised when a reservation requires audited administrative resolution."""


class IdempotencyConflictError(RuntimeError):
    """Raised when an idempotency key has already been used for a reservation."""


class UnsupportedCurrencyError(SecurityViolationError):
    """Raised when no cumulative budget policy exists for a requested currency."""


class UnifiedGovernanceEngine:
    def __init__(
        self,
        budget_db_path: str | Path | None = None,
        policy_file_path: str | Path | None = None,
    ):
        self._policy_lock = threading.RLock()
        self.policy_file_path = Path(
            policy_file_path
            or os.getenv(
                "GATEWAY_POLICY_FILE",
                Path(__file__).resolve().parents[1] / "config" / "policies.yaml",
            )
        )
        self.budget_window_seconds = int(
            os.getenv("GATEWAY_BUDGET_WINDOW_SECONDS", "3600")
        )
        if self.budget_window_seconds <= 0:
            raise ValueError("GATEWAY_BUDGET_WINDOW_SECONDS must be positive.")
        self.reservation_ttl_seconds = int(
            os.getenv("GATEWAY_BUDGET_RESERVATION_TTL_SECONDS", "3600")
        )
        if self.reservation_ttl_seconds <= 0:
            raise ValueError("GATEWAY_BUDGET_RESERVATION_TTL_SECONDS must be positive.")

        self.budget_db_path = Path(
            budget_db_path
            or os.getenv("GATEWAY_BUDGET_DB_PATH", "cumulative_budgets.sqlite3")
        )
        self.reload_policies()
        self._initialize_budget_store()

    @staticmethod
    def _parse_currency_limits(
        values: Any,
        setting_name: str,
        *,
        flat_currency_map: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(values, dict) or not values:
            raise ValueError(f"{setting_name} must be a non-empty mapping.")

        parsed: dict[str, Any] = {}
        for name, limits in values.items():
            if not isinstance(name, str) or not name.strip():
                raise ValueError(f"{setting_name} contains an empty name.")
            if flat_currency_map:
                currency, raw_limit = name, limits
            else:
                if not isinstance(limits, dict) or not limits:
                    raise ValueError(
                        f"{setting_name} for {name!r} must be a non-empty currency mapping."
                    )
                role_limits = {}
                for currency, raw_limit in limits.items():
                    if not isinstance(currency, str) or len(currency.strip()) != 3:
                        raise ValueError(
                            f"{setting_name} currency codes must contain three letters."
                        )
                    try:
                        parsed_limit = Decimal(str(raw_limit))
                    except InvalidOperation as exc:
                        raise ValueError(
                            f"{setting_name} for {name!r}/{currency} must be a decimal."
                        ) from exc
                    if not parsed_limit.is_finite() or parsed_limit <= 0:
                        raise ValueError(
                            f"{setting_name} for {name!r}/{currency} must be positive."
                        )
                    role_limits[currency.strip().upper()] = parsed_limit
                parsed[name] = role_limits
                continue

            if not isinstance(currency, str) or len(currency.strip()) != 3:
                raise ValueError(f"{setting_name} currency codes must contain three letters.")
            try:
                parsed_limit = Decimal(str(raw_limit))
            except InvalidOperation as exc:
                raise ValueError(
                    f"{setting_name} for {currency} must be a decimal."
                ) from exc
            if not parsed_limit.is_finite() or parsed_limit <= 0:
                raise ValueError(f"{setting_name} for {currency} must be positive.")
            parsed[currency.strip().upper()] = parsed_limit
        return parsed

    def reload_policies(self) -> str:
        try:
            policy_content = self.policy_file_path.read_bytes()
            policy_document = yaml.safe_load(policy_content.decode("utf-8-sig"))
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            raise RuntimeError(
                f"Could not load gateway policy file {self.policy_file_path}."
            ) from exc
        if not isinstance(policy_document, dict):
            raise ValueError("Gateway policy file must contain a YAML mapping.")
        policy = policy_document.get("gateway_policy")
        if not isinstance(policy, dict):
            raise ValueError("Gateway policy file must define a gateway_policy mapping.")

        critical_limits = self._parse_currency_limits(
            policy.get("critical_financial_limits"),
            "critical_financial_limits",
            flat_currency_map=True,
        )
        for setting, configured_limit in os.environ.items():
            if not setting.startswith("GATEWAY_CRITICAL_LIMIT_"):
                continue
            currency = setting[len("GATEWAY_CRITICAL_LIMIT_") :].upper()
            critical_limits.update(
                self._parse_currency_limits(
                    {currency: configured_limit},
                    setting,
                    flat_currency_map=True,
                )
            )

        transaction_limits = self._parse_currency_limits(
            policy.get("role_transaction_limits"),
            "role_transaction_limits",
        )
        budget_limits = self._parse_currency_limits(
            policy.get("role_budget_limits"),
            "role_budget_limits",
        )
        configured_budget_limits = json.loads(
            os.getenv("GATEWAY_ROLE_BUDGET_LIMITS", "{}")
        )
        if not isinstance(configured_budget_limits, dict):
            raise ValueError("GATEWAY_ROLE_BUDGET_LIMITS must be a JSON object.")
        for role, configured_limits in configured_budget_limits.items():
            if not isinstance(role, str) or not role:
                raise ValueError("Cumulative budget role names must be non-empty strings.")
            role_limits = (
                configured_limits
                if isinstance(configured_limits, dict)
                else {"USD": configured_limits}
            )
            budget_limits[role] = self._parse_currency_limits(
                {role: role_limits},
                "GATEWAY_ROLE_BUDGET_LIMITS",
            )[role]

        tool_permissions = policy.get("tool_permissions")
        if not isinstance(tool_permissions, dict) or not tool_permissions:
            raise ValueError("tool_permissions must be a non-empty mapping.")
        for tool, roles in tool_permissions.items():
            if (
                not isinstance(tool, str)
                or not tool
                or not isinstance(roles, list)
                or not roles
                or any(not isinstance(role, str) or not role for role in roles)
            ):
                raise ValueError("Each tool permission must have a non-empty role list.")
        revision = hashlib.sha256(policy_content).hexdigest()
        role_budget_limits = {
            role: limits["USD"]
            for role, limits in budget_limits.items()
            if "USD" in limits
        }
        role_limits = {
            role: limits["USD"]
            for role, limits in transaction_limits.items()
            if "USD" in limits
        }
        with self._policy_lock:
            self.critical_financial_limits = critical_limits
            self.role_currency_transaction_limits = transaction_limits
            self.role_currency_budget_limits = budget_limits
            self.role_budget_limits = role_budget_limits
            self.role_limits = role_limits
            self.tool_permissions = {
                tool: list(roles) for tool, roles in tool_permissions.items()
            }
            allowed_rec = policy.get("allowed_recipients")
            self.allowed_recipients = [str(r).strip() for r in allowed_rec] if isinstance(allowed_rec, list) else []
            self.policy_revision = revision
        logger.info(
            "Reloaded gateway policy revision=%s transaction_limits=%s "
            "cumulative_limits=%s",
            revision,
            transaction_limits,
            budget_limits,
        )
        return revision

    def _initialize_budget_store(self) -> None:
        try:
            self.budget_db_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.budget_db_path, timeout=10) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cumulative_budget_reservations (
                        reservation_id TEXT PRIMARY KEY,
                        role TEXT NOT NULL,
                        user_id TEXT NOT NULL,
                        amount TEXT NOT NULL,
                        reserved_at REAL NOT NULL,
                        status TEXT NOT NULL DEFAULT 'COMMITTED',
                        expires_at REAL,
                        committed_at TEXT,
                        idempotency_key TEXT UNIQUE,
                        execution_token TEXT,
                        currency TEXT NOT NULL DEFAULT 'USD'
                    )
                    """
                )
                columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(cumulative_budget_reservations)"
                    )
                }
                if "status" not in columns:
                    connection.execute(
                        "ALTER TABLE cumulative_budget_reservations "
                        "ADD COLUMN status TEXT NOT NULL DEFAULT 'COMMITTED'"
                    )
                if "expires_at" not in columns:
                    connection.execute(
                        "ALTER TABLE cumulative_budget_reservations "
                        "ADD COLUMN expires_at REAL"
                    )
                if "committed_at" not in columns:
                    connection.execute(
                        "ALTER TABLE cumulative_budget_reservations "
                        "ADD COLUMN committed_at TEXT"
                    )
                if "idempotency_key" not in columns:
                    connection.execute(
                        "ALTER TABLE cumulative_budget_reservations "
                        "ADD COLUMN idempotency_key TEXT"
                    )
                if "execution_token" not in columns:
                    connection.execute(
                        "ALTER TABLE cumulative_budget_reservations "
                        "ADD COLUMN execution_token TEXT"
                    )
                if "currency" not in columns:
                    connection.execute(
                        "ALTER TABLE cumulative_budget_reservations "
                        "ADD COLUMN currency TEXT NOT NULL DEFAULT 'USD'"
                    )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS idempotency_registry (
                        idempotency_key TEXT PRIMARY KEY,
                        reservation_id TEXT,
                        created_at TEXT NOT NULL,
                        role TEXT NOT NULL,
                        amount TEXT NOT NULL,
                        currency TEXT NOT NULL,
                        tool_name TEXT,
                        context_user_id TEXT,
                        payload_hash TEXT,
                        status TEXT NOT NULL DEFAULT 'PENDING',
                        updated_at TEXT
                    )
                    """
                )
                registry_columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(idempotency_registry)"
                    )
                }
                if "tool_name" not in registry_columns:
                    connection.execute(
                        "ALTER TABLE idempotency_registry ADD COLUMN tool_name TEXT"
                    )
                if "context_user_id" not in registry_columns:
                    connection.execute(
                        "ALTER TABLE idempotency_registry ADD COLUMN context_user_id TEXT"
                    )
                if "payload_hash" not in registry_columns:
                    connection.execute(
                        "ALTER TABLE idempotency_registry ADD COLUMN payload_hash TEXT"
                    )
                if "status" not in registry_columns:
                    connection.execute(
                        "ALTER TABLE idempotency_registry "
                        "ADD COLUMN status TEXT NOT NULL DEFAULT 'PENDING'"
                    )
                if "updated_at" not in registry_columns:
                    connection.execute(
                        "ALTER TABLE idempotency_registry ADD COLUMN updated_at TEXT"
                    )
                connection.execute(
                    """
                    INSERT OR IGNORE INTO idempotency_registry
                        (idempotency_key, reservation_id, created_at, role, amount,
                         currency, tool_name, context_user_id, payload_hash, status, updated_at)
                    SELECT idempotency_key, reservation_id,
                           strftime('%Y-%m-%dT%H:%M:%fZ', reserved_at, 'unixepoch'),
                           role, amount, currency, 'wire_transfer', user_id, NULL,
                           CASE WHEN status = 'COMMITTED' THEN 'COMMITTED'
                                WHEN status = 'RELEASED' THEN 'ABORTED'
                                ELSE 'PENDING' END,
                           strftime('%Y-%m-%dT%H:%M:%fZ', reserved_at, 'unixepoch')
                    FROM cumulative_budget_reservations
                    WHERE idempotency_key IS NOT NULL
                    """
                )
                connection.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS budget_reservations_idempotency_key
                    ON cumulative_budget_reservations (idempotency_key)
                    WHERE idempotency_key IS NOT NULL
                    """
                )
                connection.execute(
                    """
                    UPDATE cumulative_budget_reservations
                    SET status = 'EXPIRED_UNRESOLVED'
                    WHERE status = 'EXPIRED'
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS budget_reconciliation_audit (
                        audit_id TEXT PRIMARY KEY,
                        reservation_id TEXT NOT NULL,
                        previous_status TEXT NOT NULL,
                        resolution TEXT NOT NULL,
                        proof_json TEXT NOT NULL,
                        operator_id TEXT NOT NULL,
                        reconciled_at REAL NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS budget_reservations_identity_time
                    ON cumulative_budget_reservations (role, user_id, reserved_at)
                    """
                )
        except sqlite3.Error as exc:
            raise RuntimeError(
                f"Could not initialize cumulative budget store at {self.budget_db_path}."
            ) from exc

    def _cleanup_stale_reservations(
        self,
        connection: sqlite3.Connection,
        now: float,
        window_start: float,
    ) -> None:
        connection.execute(
            """
            UPDATE cumulative_budget_reservations
            SET status = 'EXPIRED_UNRESOLVED'
            WHERE status = 'RESERVED' AND expires_at <= ?
            """,
            (now,),
        )
        connection.execute(
            """
            DELETE FROM cumulative_budget_reservations
            WHERE reserved_at <= ? AND status = 'RELEASED'
            """,
            (window_start,),
        )

    @staticmethod
    def _idempotency_payload_hash(
        tool_name: str,
        role: str,
        context_user_id: str,
        amount: str,
        currency: str,
    ) -> str:
        payload = {
            "tool_name": tool_name,
            "role": role,
            "context_user_id": context_user_id,
            "amount": amount,
            "currency": currency,
        }
        canonical_payload = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(canonical_payload).hexdigest()

    @staticmethod
    def _cached_confirmation(
        idempotency_key: str,
        reservation_id: str | None,
    ) -> dict[str, Any]:
        return {
            "status": "COMMITTED",
            "idempotency_key": idempotency_key,
            "reservation_id": reservation_id,
            "cached": True,
        }

    def reserve_budget(
        self,
        role: str,
        user_id: str,
        amount: Decimal,
        idempotency_key: str | None = None,
        currency: str = "USD",
        tool_name: str = "wire_transfer",
        payload_hash: str | None = None,
    ) -> tuple[bool, Decimal, str | None, str | None]:
        result = self.reserve_budget_with_confirmation(
            role,
            user_id,
            amount,
            idempotency_key,
            currency,
            tool_name,
            payload_hash,
        )
        return result[:4]

    def reserve_budget_with_confirmation(
        self,
        role: str,
        user_id: str,
        amount: Decimal,
        idempotency_key: str | None = None,
        currency: str = "USD",
        tool_name: str = "wire_transfer",
        payload_hash: str | None = None,
    ) -> tuple[bool, Decimal, str | None, str | None, dict[str, Any] | None]:
        if not user_id or not amount.is_finite() or amount <= 0:
            return False, Decimal("0"), None, None, None
        if idempotency_key is None:
            idempotency_key = uuid.uuid4().hex
        elif not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise ValueError("Idempotency key must be a non-empty string.")
        if not isinstance(currency, str) or not currency.strip():
            raise ValueError("Currency must be a non-empty string.")
        currency = currency.strip().upper()
        with self._policy_lock:
            budget_limit = self.role_currency_budget_limits.get(role, {}).get(currency)
        if budget_limit is None:
            raise UnsupportedCurrencyError(
                f"No cumulative budget policy is configured for role {role!r} in {currency}."
            )
        if payload_hash is None:
            payload_hash = self._idempotency_payload_hash(
                tool_name, role, user_id, str(amount), currency
            )

        now = time.time()
        window_start = now - self.budget_window_seconds
        window_start_utc = datetime.fromtimestamp(
            window_start, timezone.utc
        ).isoformat().replace("+00:00", "Z")
        reservation_id = uuid.uuid4().hex
        execution_token = uuid.uuid4().hex
        try:
            with sqlite3.connect(
                self.budget_db_path,
                timeout=10,
                isolation_level=None,
            ) as connection:
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("BEGIN IMMEDIATE")
                self._cleanup_stale_reservations(connection, now, window_start)
                existing = connection.execute(
                    """
                    SELECT reservation_id, payload_hash, status, role,
                           context_user_id, tool_name, amount, currency
                    FROM idempotency_registry WHERE idempotency_key = ?
                    """,
                    (idempotency_key,),
                ).fetchone()
                if existing:
                    if (
                        existing[1] != payload_hash
                        or existing[3] != role
                        or existing[4] != user_id
                        or existing[5] != tool_name
                        or existing[6] != str(amount)
                        or existing[7] != currency
                    ):
                        connection.rollback()
                        raise IdempotencyConflictError(
                            "Idempotency key was previously used with a different payload."
                        )
                    if existing[2] == "COMMITTED":
                        connection.commit()
                        return (
                            True,
                            Decimal(existing[6]),
                            existing[0],
                            None,
                            self._cached_confirmation(idempotency_key, existing[0]),
                        )
                    if existing[2] != "ABORTED":
                        connection.rollback()
                        raise IdempotencyConflictError(
                            "Idempotency key already has an in-flight operation."
                        )
                reservations = connection.execute(
                    """
                    SELECT amount
                    FROM cumulative_budget_reservations
                                        WHERE role = ? AND user_id = ? AND currency = ?
                                            AND status != 'RELEASED'
                                            AND (status != 'COMMITTED' OR
                                                     (committed_at IS NOT NULL AND committed_at >= ?) OR
                                                     (committed_at IS NULL AND reserved_at >= ?))
                    """,
                                        (role, user_id, currency, window_start_utc, window_start),
                ).fetchall()
                current_total = sum(
                    (Decimal(row[0]) for row in reservations),
                    Decimal("0"),
                )
                next_total = current_total + amount
                if next_total > budget_limit:
                    connection.commit()
                    return False, current_total, None, None, None
                updated_at = datetime.now(timezone.utc).isoformat().replace(
                    "+00:00", "Z"
                )
                if existing:
                    old_reservation_id = existing[0]
                    if old_reservation_id:
                        connection.execute(
                            """
                            UPDATE cumulative_budget_reservations
                            SET idempotency_key = NULL
                            WHERE reservation_id = ? AND status = 'RELEASED'
                            """,
                            (old_reservation_id,),
                        )
                    connection.execute(
                        """
                        UPDATE idempotency_registry
                        SET reservation_id = ?, status = 'PENDING', updated_at = ?,
                            amount = ?, currency = ?
                        WHERE idempotency_key = ? AND status = 'ABORTED'
                        """,
                        (
                            reservation_id,
                            updated_at,
                            str(amount),
                            currency,
                            idempotency_key,
                        ),
                    )
                else:
                    connection.execute(
                        """
                        INSERT INTO idempotency_registry
                            (idempotency_key, reservation_id, created_at, role, amount,
                             currency, tool_name, context_user_id, payload_hash,
                             status, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)
                        """,
                        (
                            idempotency_key,
                            reservation_id,
                            updated_at,
                            role,
                            str(amount),
                            currency,
                            tool_name,
                            user_id,
                            payload_hash,
                            updated_at,
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO cumulative_budget_reservations
                        (reservation_id, role, user_id, amount, reserved_at,
                         status, expires_at, idempotency_key, execution_token,
                         currency)
                    VALUES (?, ?, ?, ?, ?, 'RESERVED', ?, ?, ?, ?)
                    """,
                    (
                        reservation_id,
                        role,
                        user_id,
                        str(amount),
                        now,
                        now + self.reservation_ttl_seconds,
                        idempotency_key,
                        execution_token,
                        currency,
                    ),
                )
                connection.commit()
                return True, next_total, reservation_id, execution_token, None
        except sqlite3.IntegrityError as exc:
            raise IdempotencyConflictError(
                f"Idempotency key {idempotency_key!r} is already registered."
            ) from exc
        except (sqlite3.Error, InvalidOperation) as exc:
            raise RuntimeError("Could not atomically reserve cumulative budget.") from exc

    def register_mutation_idempotency_key(
        self,
        idempotency_key: str,
        tool_name: str,
        role: str,
        context_user_id: str,
        payload_hash: str,
    ) -> dict[str, Any] | None:
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise ValueError("Idempotency key must be a non-empty string.")
        if not tool_name or not role or not context_user_id:
            raise ValueError("Tool name, role, and context user ID are required.")
        try:
            with sqlite3.connect(
                self.budget_db_path,
                timeout=10,
                isolation_level=None,
            ) as connection:
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    """
                    SELECT reservation_id, payload_hash, status, role,
                           context_user_id, tool_name
                    FROM idempotency_registry WHERE idempotency_key = ?
                    """,
                    (idempotency_key,),
                ).fetchone()
                now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                if existing:
                    if (
                        existing[1] != payload_hash
                        or existing[3] != role
                        or existing[4] != context_user_id
                        or existing[5] != tool_name
                    ):
                        connection.rollback()
                        raise IdempotencyConflictError(
                            "Idempotency key was previously used with a different payload."
                        )
                    if existing[2] == "COMMITTED":
                        connection.commit()
                        return self._cached_confirmation(idempotency_key, existing[0])
                    if existing[2] != "ABORTED":
                        connection.rollback()
                        raise IdempotencyConflictError(
                            "Idempotency key already has an in-flight operation."
                        )
                    connection.execute(
                        """
                        UPDATE idempotency_registry
                        SET status = 'PENDING', updated_at = ?, reservation_id = NULL
                        WHERE idempotency_key = ? AND status = 'ABORTED'
                        """,
                        (now, idempotency_key),
                    )
                else:
                    connection.execute(
                        """
                        INSERT INTO idempotency_registry
                            (idempotency_key, reservation_id, created_at, role, amount,
                             currency, tool_name, context_user_id, payload_hash,
                             status, updated_at)
                        VALUES (?, NULL, ?, ?, '0', 'N/A', ?, ?, ?, 'PENDING', ?)
                        """,
                        (
                            idempotency_key,
                            now,
                            role,
                            tool_name,
                            context_user_id,
                            payload_hash,
                            now,
                        ),
                    )
                connection.commit()
                return None
        except IdempotencyConflictError:
            raise
        except sqlite3.IntegrityError as exc:
            raise IdempotencyConflictError(
                f"Idempotency key {idempotency_key!r} is already registered."
            ) from exc
        except sqlite3.Error as exc:
            raise RuntimeError("Could not register mutation idempotency key.") from exc

    def mark_idempotency_status(
        self,
        idempotency_key: str,
        status: str,
    ) -> None:
        if status not in {"COMMITTED", "ABORTED"}:
            raise ValueError("Idempotency status must be COMMITTED or ABORTED.")
        try:
            with sqlite3.connect(self.budget_db_path, timeout=10) as connection:
                connection.execute(
                    """
                    UPDATE idempotency_registry
                    SET status = ?, updated_at = ?
                    WHERE idempotency_key = ? AND status = 'PENDING'
                    """,
                    (
                        status,
                        datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        idempotency_key,
                    ),
                )
        except sqlite3.Error as exc:
            raise RuntimeError("Could not update mutation idempotency status.") from exc

    def commit_budget(
        self,
        reservation_id: str,
        execution_token: str | None = None,
    ) -> bool:
        if not reservation_id:
            raise BudgetStateConflictError("Budget reservation ID is required.")
        if not isinstance(execution_token, str) or not execution_token.strip():
            raise BudgetStateConflictError("A valid execution token is required to commit.")
        now = time.time()
        committed_at = datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
        try:
            with sqlite3.connect(
                self.budget_db_path,
                timeout=10,
                isolation_level=None,
            ) as connection:
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    UPDATE cumulative_budget_reservations
                    SET status = 'EXPIRED_UNRESOLVED'
                    WHERE reservation_id = ? AND status = 'RESERVED'
                      AND expires_at <= ?
                    """,
                    (reservation_id, now),
                )
                cursor = connection.execute(
                    """
                    UPDATE cumulative_budget_reservations
                    SET status = 'COMMITTED', committed_at = ?, execution_token = NULL
                    WHERE reservation_id = ?
                      AND execution_token = ?
                      AND status IN ('RESERVED', 'EXPIRED_UNRESOLVED')
                    """,
                    (committed_at, reservation_id, execution_token),
                )
                if cursor.rowcount == 1:
                    registry_row = connection.execute(
                        "SELECT idempotency_key FROM cumulative_budget_reservations "
                        "WHERE reservation_id = ?",
                        (reservation_id,),
                    ).fetchone()
                    if registry_row and registry_row[0]:
                        connection.execute(
                            """
                            UPDATE idempotency_registry
                            SET status = 'COMMITTED', updated_at = ?
                            WHERE idempotency_key = ? AND status = 'PENDING'
                            """,
                            (committed_at, registry_row[0]),
                        )
                    connection.commit()
                    return True
                connection.commit()
        except sqlite3.Error as exc:
            raise RuntimeError("Could not commit cumulative budget reservation.") from exc
        raise BudgetStateConflictError(
            f"Budget reservation {reservation_id!r} is not in a committable state."
        )

    def flag_for_reconciliation(self, reservation_id: str) -> bool:
        transitioned = self._transition_budget_status(
            reservation_id,
            ("RESERVED", "EXPIRED_UNRESOLVED"),
            "RECONCILIATION_REQUIRED",
        )
        if not transitioned:
            raise BudgetStateConflictError(
                f"Budget reservation {reservation_id!r} cannot be flagged for reconciliation."
            )
        return True

    def release_budget(self, reservation_id: str) -> bool:
        if not reservation_id:
            return False
        try:
            with sqlite3.connect(
                self.budget_db_path,
                timeout=10,
                isolation_level=None,
            ) as connection:
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("BEGIN IMMEDIATE")
                key_row = connection.execute(
                    "SELECT idempotency_key FROM cumulative_budget_reservations "
                    "WHERE reservation_id = ? AND status = 'RESERVED'",
                    (reservation_id,),
                ).fetchone()
                cursor = connection.execute(
                    """
                    UPDATE cumulative_budget_reservations
                    SET status = 'RELEASED', idempotency_key = NULL
                    WHERE reservation_id = ? AND status = 'RESERVED'
                    """,
                    (reservation_id,),
                )
                if cursor.rowcount == 1:
                    if key_row and key_row[0]:
                        connection.execute(
                            """
                            UPDATE idempotency_registry
                            SET status = 'ABORTED', updated_at = ?
                            WHERE idempotency_key = ? AND status = 'PENDING'
                            """,
                            (
                                datetime.now(timezone.utc).isoformat().replace(
                                    "+00:00", "Z"
                                ),
                                key_row[0],
                            ),
                        )
                    connection.commit()
                    return True
                row = connection.execute(
                    """
                    SELECT status
                    FROM cumulative_budget_reservations
                    WHERE reservation_id = ?
                    """,
                    (reservation_id,),
                ).fetchone()
                connection.commit()
        except sqlite3.Error as exc:
            raise RuntimeError("Could not release cumulative budget reservation.") from exc
        if row and row[0] in {
            "EXPIRED_UNRESOLVED",
            "RECONCILIATION_REQUIRED",
        }:
            raise ReconciliationProofRequiredError(
                "Provider proof is required to release this unresolved reservation."
            )
        return False

    def reconcile_reservation(
        self,
        reservation_id: str,
        resolution: str,
        proof: dict[str, Any],
        operator_id: str,
        operator_context: Any,
        nonce_store: Any,
    ) -> bool:
        operator = self.verify_operator_context(operator_context)
        if not isinstance(operator_id, str) or operator_id != operator[
            "identity"
        ]["user_id"]:
            raise SecurityViolationError(
                "Operator ID must match the verified operator identity."
            )
        if not isinstance(resolution, str) or resolution not in (
            "RELEASED",
            "COMMITTED",
        ):
            raise ValueError("Resolution must be 'RELEASED' or 'COMMITTED'.")
        if not isinstance(proof, dict) or not proof:
            raise ValueError("Reconciliation proof must be a non-empty dictionary.")
        if operator.get("target_reservation_id") != reservation_id:
            raise SecurityViolationError(
                "Operator context is not scoped to this reservation."
            )
        nonce = operator.get("nonce")
        if not isinstance(nonce, str) or not nonce.strip():
            raise SecurityViolationError("Operator context requires a nonce.")
        if proof.get("provider_status") not in (
            "CONFIRMED_EXECUTED",
            "CONFIRMED_NOT_EXECUTED",
        ):
            raise ReconciliationProofRequiredError(
                "Provider proof must contain a verified provider_status."
            )
        if not isinstance(proof.get("idempotency_key"), str) or not proof[
            "idempotency_key"
        ].strip():
            raise ReconciliationProofRequiredError(
                "Provider proof must include an idempotency_key."
            )
        if (resolution == "COMMITTED") != (
            proof["provider_status"] == "CONFIRMED_EXECUTED"
        ):
            raise ReconciliationProofRequiredError(
                "Provider status does not match the requested resolution."
            )
        if not isinstance(proof.get("provider_ref"), str) or not proof[
            "provider_ref"
        ].strip():
            raise ReconciliationProofRequiredError(
                "Provider proof must include a non-empty provider_ref."
            )
        if not reservation_id:
            raise ValueError("Reservation ID must be non-empty.")
        try:
            proof_amount = Decimal(str(proof.get("amount")))
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise ReconciliationProofRequiredError(
                "Provider proof amount is invalid."
            ) from exc
        if not proof_amount.is_finite():
            raise ReconciliationProofRequiredError("Provider proof amount is invalid.")
        try:
            with sqlite3.connect(self.budget_db_path, timeout=10) as connection:
                reservation = connection.execute(
                    """
                    SELECT status, idempotency_key, amount, currency
                    FROM cumulative_budget_reservations
                    WHERE reservation_id = ?
                    """,
                    (reservation_id,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise RuntimeError("Could not load reservation for reconciliation.") from exc
        if not reservation or reservation[0] not in {
            "EXPIRED_UNRESOLVED",
            "RECONCILIATION_REQUIRED",
        }:
            raise BudgetStateConflictError(
                f"Budget reservation {reservation_id!r} is not unresolved."
            )
        bound_key = reservation[1]
        if (
            not isinstance(bound_key, str)
            or not bound_key
            or not hmac.compare_digest(proof["idempotency_key"], bound_key)
        ):
            raise ReconciliationProofRequiredError(
                "Provider proof idempotency key does not match the reservation."
            )
        try:
            reserved_amount = Decimal(reservation[2])
        except InvalidOperation as exc:
            raise RuntimeError("Stored reservation amount is invalid.") from exc
        if proof_amount != reserved_amount:
            raise ReconciliationProofRequiredError(
                "Provider proof amount does not match the reservation."
            )
        currency = str(reservation[3] or "USD").upper()
        proof_currency = proof.get("currency")
        if not isinstance(proof_currency, str) or proof_currency.upper() != currency:
            raise ReconciliationProofRequiredError(
                "Provider proof currency does not match the reservation."
            )
        provider_ref = proof["provider_ref"].strip()
        canonical_proof = (
            f"{bound_key}:{reservation_id}:{reserved_amount}:{currency}:"
            f"{provider_ref}:{proof['provider_status']}"
        ).encode("utf-8")
        provider_signature = proof.get("provider_signature")
        provider_secret = os.getenv("GATEWAY_PROVIDER_PROOF_HMAC_SECRET")
        signature_valid = False
        if (
            isinstance(provider_signature, str)
            and provider_signature.isascii()
            and len(provider_signature) == hashlib.sha256().digest_size * 2
            and isinstance(provider_secret, str)
            and provider_secret
        ):
            expected_signature = hmac.new(
                provider_secret.encode("utf-8"),
                canonical_proof,
                hashlib.sha256,
            ).hexdigest()
            signature_valid = hmac.compare_digest(
                provider_signature, expected_signature
            )
        if not signature_valid:
            raise ReconciliationProofRequiredError(
                "Provider proof HMAC signature is invalid."
            )
        try:
            proof_json = json.dumps(
                proof,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("Reconciliation proof must be valid JSON data.") from exc

        expires_at = float(operator["expires_at"])
        if not nonce_store.consume_nonce(nonce, expires_at):
            raise SecurityViolationError(
                "Operator context nonce has already been consumed."
            )

        try:
            with sqlite3.connect(
                self.budget_db_path,
                timeout=10,
                isolation_level=None,
            ) as connection:
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT status, idempotency_key, amount, currency
                    FROM cumulative_budget_reservations
                    WHERE reservation_id = ?
                    """,
                    (reservation_id,),
                ).fetchone()
                if not row or row[0] not in {
                    "EXPIRED_UNRESOLVED",
                    "RECONCILIATION_REQUIRED",
                }:
                    connection.rollback()
                    raise BudgetStateConflictError(
                        f"Budget reservation {reservation_id!r} is not unresolved."
                    )
                if row[1] != bound_key or row[2] != reservation[2] or row[3] != reservation[3]:
                    connection.rollback()
                    raise ReconciliationProofRequiredError(
                        "Reservation attributes changed during reconciliation."
                    )
                previous_status = row[0]
                committed_at = (
                    datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                    if resolution == "COMMITTED"
                    else None
                )
                cursor = connection.execute(
                    """
                    UPDATE cumulative_budget_reservations
                    SET status = ?, committed_at = ?,
                        idempotency_key = CASE WHEN ? = 'RELEASED' THEN NULL
                                               ELSE idempotency_key END
                    WHERE reservation_id = ? AND status = ?
                    """,
                    (
                        resolution,
                        committed_at,
                        resolution,
                        reservation_id,
                        previous_status,
                    ),
                )
                if cursor.rowcount != 1:
                    connection.rollback()
                    raise BudgetStateConflictError(
                        f"Budget reservation {reservation_id!r} changed during reconciliation."
                    )
                connection.execute(
                    """
                    INSERT INTO budget_reconciliation_audit
                        (audit_id, reservation_id, previous_status, resolution,
                         proof_json, operator_id, reconciled_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        uuid.uuid4().hex,
                        reservation_id,
                        previous_status,
                        resolution,
                        proof_json,
                        operator["identity"]["user_id"],
                        time.time(),
                    ),
                )
                connection.execute(
                    """
                    UPDATE idempotency_registry
                    SET status = ?, updated_at = ?
                    WHERE idempotency_key = ?
                    """,
                    (
                        "ABORTED" if resolution == "RELEASED" else "COMMITTED",
                        datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        bound_key,
                    ),
                )
                connection.commit()
                return True
        except sqlite3.Error as exc:
            raise RuntimeError("Could not persist budget reconciliation.") from exc

    @staticmethod
    def verify_operator_context(operator_context: Any) -> dict[str, Any]:
        if not isinstance(operator_context, dict):
            raise SecurityViolationError("A signed operator context is required.")
        signature = operator_context.get("__signature__")
        unsigned_context = {
            key: value
            for key, value in operator_context.items()
            if key != "__signature__"
        }
        secret = os.getenv("GATEWAY_CONTEXT_HMAC_SECRET")
        if (
            not isinstance(signature, str)
            or len(signature) != hashlib.sha256().digest_size * 2
            or not signature.isascii()
            or not isinstance(secret, str)
            or not secret
        ):
            raise SecurityViolationError("Operator context signature is invalid.")
        try:
            expected_signature = hmac.new(
                secret.encode("utf-8"),
                json.dumps(
                    unsigned_context,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
        except (TypeError, ValueError) as exc:
            raise SecurityViolationError(
                "Operator context could not be verified."
            ) from exc
        if not hmac.compare_digest(signature, expected_signature):
            raise SecurityViolationError("Operator context signature does not match.")
        role = unsigned_context.get("role")
        if not isinstance(role, str) or role not in (
            "reconciler",
            "admin",
            "governance_admin",
        ):
            raise SecurityViolationError(
                "Operator role is not authorized to reconcile reservations."
            )
        identity = unsigned_context.get("identity")
        if not isinstance(identity, dict) or not isinstance(
            identity.get("user_id"), str
        ) or not identity["user_id"].strip():
            raise SecurityViolationError("Signed operator identity is incomplete.")
        expires_at = unsigned_context.get("expires_at")
        if (
            isinstance(expires_at, bool)
            or not isinstance(expires_at, (int, float))
            or not math.isfinite(expires_at)
            or expires_at <= time.time()
        ):
            raise SecurityViolationError("Operator context has expired or is invalid.")
        return unsigned_context

    def _transition_budget_status(
        self,
        reservation_id: str,
        allowed_statuses: tuple[str, ...],
        next_status: str,
    ) -> bool:
        if not reservation_id:
            return False
        placeholders = ", ".join("?" for _ in allowed_statuses)
        try:
            with sqlite3.connect(
                self.budget_db_path,
                timeout=10,
                isolation_level=None,
            ) as connection:
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    f"""
                    UPDATE cumulative_budget_reservations
                    SET status = ?
                    WHERE reservation_id = ? AND status IN ({placeholders})
                    """,
                    (next_status, reservation_id, *allowed_statuses),
                )
                connection.commit()
                return cursor.rowcount == 1
        except sqlite3.Error as exc:
            raise RuntimeError("Could not transition cumulative budget reservation.") from exc

    def evaluate(self, payload: Dict[str, Any]) -> Tuple[int, List[str], Dict[str, Any]]:
        dof = 0
        violations = []
        metadata = {}

        tool = payload.get("tool")
        params = payload.get("parameters", {})
        context = payload.get("context", {})

        if not isinstance(tool, str) or not tool:
            return 2, ["Missing target tool specification"], metadata

        if tool not in self.tool_permissions:
            return 2, ["Security Invariant: Tool is unrecognized (Fail-Closed)"], metadata

        if not isinstance(params, dict) or not isinstance(context, dict):
            return 2, ["Malformed parameters or identity context (Fail-Closed)"], metadata

        role = context.get("role")
        if not isinstance(role, str) or not role:
            return 2, ["Unauthenticated invocation: Role missing from verified context"], metadata

        with self._policy_lock:
            allowed_roles = self.tool_permissions.get(tool)
            transaction_limits = self.role_currency_transaction_limits
            critical_limits = self.critical_financial_limits
        if allowed_roles and role not in allowed_roles:
            violations.append(f"Role '{role}' is unauthorized for execution of tool '{tool}'")
            dof += 2
            return dof, violations, metadata

        if tool == "wire_transfer":
            recipient_val = params.get("recipient")
            if recipient_val is not None:
                if not isinstance(recipient_val, str) or not recipient_val.strip():
                    violations.append("Recipient identifier must be a non-empty string.")
                    dof += 2
                elif self.allowed_recipients and recipient_val.strip() not in self.allowed_recipients:
                    violations.append(f"Recipient '{recipient_val}' is not in allowed recipient policy")
                    dof += 2
            amount_raw = params.get("amount")
            if amount_raw is None:
                violations.append("Parameter 'amount' is mandatory for wire_transfer")
                dof += 2
            else:
                try:
                    amount = Decimal(str(amount_raw))
                    currency_raw = params.get("currency", "USD")
                    currency = (
                        currency_raw.strip().upper()
                        if isinstance(currency_raw, str)
                        else ""
                    )
                    role_limit = transaction_limits.get(role, {}).get(currency)
                    critical_limit = critical_limits.get(currency)
                    if not amount.is_finite() or amount <= Decimal("0"):
                        violations.append("Amount must be strictly positive")
                        dof += 2
                    elif role_limit is None or critical_limit is None:
                        violations.append(
                            f"Security Invariant: No single-transaction limit is configured for role '{role}' in currency '{currency or currency_raw}' (Fail-Closed)."
                        )
                        dof += 2
                    elif amount > role_limit:
                        violations.append(
                            f"Amount {amount} exceeds currency-specific transaction limit ({role_limit} {currency})."
                        )
                        dof += 2
                    elif amount > critical_limit:
                        violations.append(
                            f"Amount {amount} exceeds currency-specific server-enforced limit ({critical_limit} {currency}); step-up authorization required"
                        )
                        dof += 1
                        metadata["step_up_required"] = True
                except (InvalidOperation, TypeError):
                    violations.append("Invalid decimal representation for financial amount")
                    dof += 2

        return dof, violations, metadata

governance_engine = UnifiedGovernanceEngine()
