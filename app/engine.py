import os
import json
import hashlib
import hmac
import math
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, List, Tuple


class BudgetStateConflictError(RuntimeError):
    """Raised when a reservation is no longer eligible for a state transition."""


class SecurityViolationError(PermissionError):
    """Raised when a privileged governance operation is not authorized."""


class ReconciliationProofRequiredError(BudgetStateConflictError):
    """Raised when a reservation requires audited administrative resolution."""


class UnifiedGovernanceEngine:
    def __init__(self, budget_db_path: str | Path | None = None):
        self.critical_financial_limit = Decimal(os.getenv("GATEWAY_CRITICAL_LIMIT", "10000.00"))
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

        self.tool_permissions = {
            "database_drop": ["superadmin"],
            "admin_execute": ["admin"],
            "wire_transfer": ["finance_agent", "admin"],
            "read_records": ["guest", "agent", "support_agent", "finance_agent", "admin"]
        }
        self.role_limits = {
            "finance_agent": Decimal("5000.00"),
            "admin": Decimal("10000.00"),
            "agent": Decimal("500.00"),
        }
        self.role_budget_limits = {
            "finance_agent": Decimal("10000.00"),
            "admin": Decimal("25000.00"),
            "agent": Decimal("2000.00"),
        }
        configured_budget_limits = json.loads(
            os.getenv("GATEWAY_ROLE_BUDGET_LIMITS", "{}")
        )
        if not isinstance(configured_budget_limits, dict):
            raise ValueError("GATEWAY_ROLE_BUDGET_LIMITS must be a JSON object.")
        for role, limit in configured_budget_limits.items():
            if not isinstance(role, str) or not role:
                raise ValueError("Cumulative budget role names must be non-empty strings.")
            try:
                parsed_limit = Decimal(str(limit))
            except InvalidOperation as exc:
                raise ValueError(
                    f"Cumulative budget limit for {role!r} must be a decimal."
                ) from exc
            if not parsed_limit.is_finite() or parsed_limit <= 0:
                raise ValueError(
                    f"Cumulative budget limit for {role!r} must be positive."
                )
            self.role_budget_limits[role] = parsed_limit

        self.budget_db_path = Path(
            budget_db_path
            or os.getenv("GATEWAY_BUDGET_DB_PATH", "cumulative_budgets.sqlite3")
        )
        self._initialize_budget_store()

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
                        idempotency_key TEXT
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

    def reserve_budget(
        self,
        role: str,
        user_id: str,
        amount: Decimal,
        idempotency_key: str | None = None,
    ) -> tuple[bool, Decimal, str | None]:
        budget_limit = self.role_budget_limits.get(role)
        if not user_id or budget_limit is None or not amount.is_finite() or amount <= 0:
            return False, Decimal("0"), None
        if idempotency_key is None:
            idempotency_key = uuid.uuid4().hex
        elif not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise ValueError("Idempotency key must be a non-empty string.")

        now = time.time()
        window_start = now - self.budget_window_seconds
        window_start_utc = datetime.fromtimestamp(
            window_start, timezone.utc
        ).isoformat().replace("+00:00", "Z")
        reservation_id = uuid.uuid4().hex
        try:
            with sqlite3.connect(
                self.budget_db_path,
                timeout=10,
                isolation_level=None,
            ) as connection:
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("BEGIN IMMEDIATE")
                self._cleanup_stale_reservations(connection, now, window_start)
                reservations = connection.execute(
                    """
                    SELECT amount
                    FROM cumulative_budget_reservations
                                        WHERE role = ? AND user_id = ? AND status != 'RELEASED'
                                            AND (status != 'COMMITTED' OR
                                                     (committed_at IS NOT NULL AND committed_at >= ?) OR
                                                     (committed_at IS NULL AND reserved_at >= ?))
                    """,
                                        (role, user_id, window_start_utc, window_start),
                ).fetchall()
                current_total = sum(
                    (Decimal(row[0]) for row in reservations),
                    Decimal("0"),
                )
                next_total = current_total + amount
                if next_total > budget_limit:
                    connection.commit()
                    return False, current_total, None
                connection.execute(
                    """
                    INSERT INTO cumulative_budget_reservations
                        (reservation_id, role, user_id, amount, reserved_at,
                        status, expires_at, idempotency_key)
                    VALUES (?, ?, ?, ?, ?, 'RESERVED', ?, ?)
                    """,
                    (
                        reservation_id,
                        role,
                        user_id,
                        str(amount),
                        now,
                        now + self.reservation_ttl_seconds,
                        idempotency_key,
                    ),
                )
                connection.commit()
                return True, next_total, reservation_id
        except (sqlite3.Error, InvalidOperation) as exc:
            raise RuntimeError("Could not atomically reserve cumulative budget.") from exc

    def commit_budget(self, reservation_id: str) -> bool:
        if not reservation_id:
            raise BudgetStateConflictError("Budget reservation ID is required.")
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
                                        SET status = 'COMMITTED', committed_at = ?
                    WHERE reservation_id = ?
                      AND status IN ('RESERVED', 'EXPIRED_UNRESOLVED')
                    """,
                                        (committed_at, reservation_id),
                )
                if cursor.rowcount == 1:
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
                cursor = connection.execute(
                    """
                    UPDATE cumulative_budget_reservations
                    SET status = 'RELEASED'
                    WHERE reservation_id = ? AND status = 'RESERVED'
                    """,
                    (reservation_id,),
                )
                if cursor.rowcount == 1:
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
        proof_payload = {
            key: value
            for key, value in proof.items()
            if key not in {"provider_signature", "proof_payload_hash"}
        }
        try:
            canonical_proof_payload = json.dumps(
                proof_payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ReconciliationProofRequiredError(
                "Provider proof must contain canonical JSON data."
            ) from exc
        signature_valid = False
        provider_signature = proof.get("provider_signature")
        provider_secret = os.getenv("GATEWAY_PROVIDER_PROOF_HMAC_SECRET")
        if (
            isinstance(provider_signature, str)
            and provider_secret
            and len(provider_signature) == hashlib.sha256().digest_size * 2
            and provider_signature.isascii()
        ):
            expected_signature = hmac.new(
                provider_secret.encode("utf-8"),
                canonical_proof_payload,
                hashlib.sha256,
            ).hexdigest()
            signature_valid = hmac.compare_digest(
                provider_signature, expected_signature
            )
        if not signature_valid:
            raise ReconciliationProofRequiredError(
                "Provider proof HMAC signature is invalid."
            )
        if not reservation_id:
            raise ValueError("Reservation ID must be non-empty.")
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
                    SELECT status, idempotency_key
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
                if (
                    not isinstance(row[1], str)
                    or not row[1]
                    or not hmac.compare_digest(
                        proof["idempotency_key"], row[1]
                    )
                ):
                    connection.rollback()
                    raise ReconciliationProofRequiredError(
                        "Provider proof idempotency key does not match the reservation."
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
                    SET status = ?, committed_at = ?
                    WHERE reservation_id = ? AND status = ?
                    """,
                    (resolution, committed_at, reservation_id, previous_status),
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

        allowed_roles = self.tool_permissions.get(tool)
        if allowed_roles and role not in allowed_roles:
            violations.append(f"Role '{role}' is unauthorized for execution of tool '{tool}'")
            dof += 2
            return dof, violations, metadata

        if tool == "wire_transfer":
            amount_raw = params.get("amount")
            if amount_raw is None:
                violations.append("Parameter 'amount' is mandatory for wire_transfer")
                dof += 2
            else:
                try:
                    amount = Decimal(str(amount_raw))
                    if amount <= Decimal("0"):
                        violations.append("Amount must be strictly positive")
                        dof += 2
                    elif amount > self.critical_financial_limit:
                        violations.append(f"Amount {amount} exceeds critical invariant limit ({self.critical_financial_limit})")
                        dof += 2
                    else:
                        role_limit = self.role_limits.get(role)
                        if role_limit is None:
                            violations.append(
                                f"Security Invariant: Role '{role}' has no configured financial limit (Fail-Closed)."
                            )
                            dof += 2
                            return dof, violations, metadata
                        if amount > role_limit:
                            violations.append(f"Amount {amount} exceeds server-enforced limit ({role_limit}); step-up authorization required")
                            dof += 1
                            metadata["step_up_required"] = True
                except (InvalidOperation, TypeError):
                    violations.append("Invalid decimal representation for financial amount")
                    dof += 2

        return dof, violations, metadata

governance_engine = UnifiedGovernanceEngine()
