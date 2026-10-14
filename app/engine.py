import json
import os
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Tuple

class UnifiedGovernanceEngine:
    def __init__(self):
        self.critical_financial_limit = Decimal(os.getenv("GATEWAY_CRITICAL_LIMIT", "10000.00"))
        self.default_auto_approval = Decimal(os.getenv("GATEWAY_AUTO_APPROVAL_LIMIT", "1000.00"))
        
        self.tool_permissions = {
            "database_drop": ["superadmin"],
            "admin_execute": ["admin"],
            "wire_transfer": ["finance_agent", "admin"],
            "read_records": ["guest", "agent", "support_agent", "finance_agent", "admin"]
        }

    def evaluate(self, payload: Dict[str, Any]) -> Tuple[int, List[str], Dict[str, Any]]:
        dof = 0
        violations = []
        metadata = {}

        tool = payload.get("tool")
        params = payload.get("parameters", {})
        context = payload.get("context", {})

        if not tool:
            return 2, ["Missing target tool specification"], metadata

        role = context.get("role")
        if not role:
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
                        role_limit = Decimal(str(context.get("max_limit", self.default_auto_approval)))
                        if amount > role_limit:
                            violations.append(f"Amount {amount} exceeds configured limit ({role_limit}); step-up authorization required")
                            dof += 1
                except (InvalidOperation, TypeError):
                    violations.append("Invalid decimal representation for financial amount")
                    dof += 2

        return dof, violations, metadata

governance_engine = UnifiedGovernanceEngine()
