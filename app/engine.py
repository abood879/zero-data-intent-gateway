import time
import json
import hashlib

class ImmutableAuditLedger:
    def __init__(self):
        # Genesis Hash
        self.last_hash = "0" * 64

    def record_decision(self, tx_id: str, payload: dict, decision: dict) -> str:
        record = {
            "tx_id": tx_id,
            "payload": payload,
            "decision": decision,
            "timestamp": time.time(),
            "previous_hash": self.last_hash
        }
        serialized = json.dumps(record, sort_keys=True)
        current_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        self.last_hash = current_hash
        return current_hash

audit_ledger = ImmutableAuditLedger()

def resolve_vendor(vendor_name: str, approved_vendors: dict) -> str | None:
    vendor_clean = vendor_name.strip().lower()
    for official_name, aliases in approved_vendors.items():
        if vendor_clean == official_name.lower():
            return official_name
        for alias in aliases:
            if alias.lower() in vendor_clean or vendor_clean in alias.lower():
                return official_name
    return None

def evaluate_governance(payload: dict, policies: dict) -> dict:
    start_time = time.perf_counter()
    violations = []
    missing_fields = []

    # 1. التحقق من المورد مع تقليص فضاء الحالات (State Collapse)
    raw_vendor = payload.get("vendor", "")
    resolved_vendor = resolve_vendor(raw_vendor, policies.get("approved_vendors", {}))
    if not resolved_vendor:
        violations.append("UNAUTHORIZED_VENDOR")

    # 2. التحقق من القسم المصرح له
    department = payload.get("department", "")
    if department not in policies.get("allowed_departments", []):
        violations.append("UNAUTHORIZED_DEPARTMENT")

    # 3. التحقق من اعتماد الميزانية (نقص حقل)
    if not payload.get("budget_cleared", False):
        missing_fields.append("budget_cleared")

    # 4. التحقق من السقف المالي التلقائي
    amount = payload.get("amount", 0.0)
    max_limit = policies.get("max_auto_approval_limit", 5000.0)
    if amount > max_limit:
        violations.append("THRESHOLD_EXCEEDED")

    dof = len(violations) + len(missing_fields)
    latency_ms = round((time.perf_counter() - start_time) * 1000, 4)

    # الركيزة الأولى: Intent Lock (DoF = 0)
    if dof == 0:
        decision = {
            "tx_id": payload.get("id"),
            "status": "APPROVED",
            "action": "EXECUTE_INTENT_LOCKED",
            "degrees_of_freedom": 0,
            "state_collapsed": True,
            "resolved_vendor": resolved_vendor,
            "latency_ms": latency_ms,
            "tokens_consumed": 0,
            "hallucination_risk": "0.0%"
        }
        decision["audit_hash"] = audit_ledger.record_decision(payload.get("id"), payload, decision)
        return decision

    # الركيزة التفاعلية: Active Disambiguation (DoF = 1 ناتج عن نقص حقل فقط دون انتهاكات صريحة)
    if dof == 1 and len(missing_fields) == 1 and len(violations) == 0:
        field = missing_fields[0]
        decision = {
            "tx_id": payload.get("id"),
            "status": "ACTIVE_DISAMBIGUATION_REQUIRED",
            "action": "PROMPT_USER_FOR_MISSING_FIELD",
            "degrees_of_freedom": 1,
            "required_field": field,
            "prompt_to_user": f"Transaction ambiguity detected: Please confirm if '{field}' is approved to collapse state to DoF=0.",
            "latency_ms": latency_ms,
            "tokens_consumed": 0,
            "hallucination_risk": "0.0% (Deterministic Probe)"
        }
        decision["audit_hash"] = audit_ledger.record_decision(payload.get("id"), payload, decision)
        return decision

    # الركيزة الثانية: Deterministic Halt (انتهاكات واضحة متعددة DoF > 0)
    all_reasons = violations + [f"MISSING_{m.upper()}" for m in missing_fields]
    decision = {
        "tx_id": payload.get("id"),
        "status": "HALTED_AWAITING_HUMAN",
        "action": f"DETERMINISTIC_HALT ({' | '.join(all_reasons)})",
        "degrees_of_freedom": dof,
        "state_collapsed": False,
        "latency_ms": latency_ms,
        "tokens_consumed": 0,
        "hallucination_risk": "0.0% (Risk Blocked)"
    }
    decision["audit_hash"] = audit_ledger.record_decision(payload.get("id"), payload, decision)
    return decision
