import time, hashlib, json, uuid, yaml
from typing import Dict, Any, Tuple

class PolicyManager:
    def __init__(self, config_path: str = "config/policies.yaml"):
        with open(config_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f)
        self.rules = self.config.get("rules", {})
        self.max_auto_budget = self.rules.get("max_auto_approval_usd", 0.0)
        self.authorized_vendors = set(self.rules.get("authorized_vendors", []))
        self.authorized_depts = set(self.rules.get("authorized_departments", []))
        self.aliases = self.config.get("deterministic_mappings", {}).get("vendor_aliases", {})

    def resolve_alias(self, vendor: str) -> Tuple[str, bool]:
        if vendor in self.aliases:
            return self.aliases[vendor], True
        return vendor, False

class DeterministicGate:
    def __init__(self, policy: PolicyManager):
        self.policy = policy

    def evaluate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        start = time.perf_counter()
        tx_id = payload.get("id", str(uuid.uuid4())[:8])
        raw_vendor = payload.get("vendor", "")
        amount = payload.get("amount", 0.0)
        dept = payload.get("department", "")
        budget_cleared = payload.get("budget_cleared", False)

        resolved_vendor, was_collapsed = self.policy.resolve_alias(raw_vendor)
        dof = 0
        violations = []

        if resolved_vendor not in self.policy.authorized_vendors: dof += 1; violations.append("UNAUTHORIZED_VENDOR")
        if dept not in self.policy.authorized_depts: dof += 1; violations.append("UNAUTHORIZED_DEPARTMENT")
        if not budget_cleared: dof += 1; violations.append("BUDGET_NOT_CLEARED")
        if amount > self.policy.max_auto_budget: dof += 1; violations.append("THRESHOLD_EXCEEDED")

        latency_ms = (time.perf_counter() - start) * 1000
        action = "EXECUTE_INTENT_LOCKED" if dof == 0 else f"DETERMINISTIC_HALT ({' | '.join(violations)})"
        status = "APPROVED" if dof == 0 else "HALTED_AWAITING_HUMAN"

        audit_payload = {"tx_id": tx_id, "timestamp": time.time(), "payload": payload, "decision": action, "dof": dof}
        proof = hashlib.sha256(json.dumps(audit_payload, sort_keys=True).encode()).hexdigest()

        return {
            "tx_id": tx_id, "status": status, "action": action, "degrees_of_freedom": dof,
            "state_collapsed": was_collapsed, "resolved_vendor": resolved_vendor, "latency_ms": round(latency_ms, 4),
            "tokens_consumed": 0, "audit_hash": proof, "hallucination_risk": "0.0%" if dof == 0 else "0.0% (Risk Blocked)"
        }
