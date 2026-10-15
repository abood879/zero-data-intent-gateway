import os
import json
import sqlite3
import time
import uuid
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, List, Tuple


class UnifiedGovernanceEngine:
    def __init__(self, budget_db_path: str | Path | None = None):
        self.critical_financial_limit = Decimal(os.getenv("GATEWAY_CRITICAL_LIMIT", "10000.00"))
        self.budget_window_seconds = int(
            os.getenv("GATEWAY_BUDGET_WINDOW_SECONDS", "3600")
        )
        if self.budget_window_seconds <= 0:
            raise ValueError("GATEWAY_BUDGET_WINDOW_SECONDS must be positive.")

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
                        reserved_at REAL NOT NULL
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

    def reserve_cumulative_budget(
        self,
        role: str,
        user_id: str,
        amount: Decimal,
    ) -> tuple[bool, Decimal]:
        budget_limit = self.role_budget_limits.get(role)
        if not user_id or budget_limit is None or not amount.is_finite() or amount <= 0:
            return False, Decimal("0")

        now = time.time()
        window_start = now - self.budget_window_seconds
        try:
            with sqlite3.connect(
                self.budget_db_path,
                timeout=10,
                isolation_level=None,
            ) as connection:
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "DELETE FROM cumulative_budget_reservations WHERE reserved_at <= ?",
                    (window_start,),
                )
                reservations = connection.execute(
                    """
                    SELECT amount
                    FROM cumulative_budget_reservations
                    WHERE role = ? AND user_id = ? AND reserved_at > ?
                    """,
                    (role, user_id, window_start),
                ).fetchall()
                current_total = sum(
                    (Decimal(row[0]) for row in reservations),
                    Decimal("0"),
                )
                next_total = current_total + amount
                if next_total > budget_limit:
                    connection.commit()
                    return False, current_total
                connection.execute(
                    """
                    INSERT INTO cumulative_budget_reservations
                        (reservation_id, role, user_id, amount, reserved_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (uuid.uuid4().hex, role, user_id, str(amount), now),
                )
                connection.commit()
                return True, next_total
        except (sqlite3.Error, InvalidOperation) as exc:
            raise RuntimeError("Could not atomically reserve cumulative budget.") from exc

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
