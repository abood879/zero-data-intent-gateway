import hashlib
import json
import time
import os
from typing import Dict, Any

# التحقق من وجود مكتبات الاتصال الموزع
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

class HybridAuditLedger:
    def __init__(self, redis_url: str = "redis://redis:6379/0"):
        self.redis_client = None
        self.chain = []
        self.last_hash = "GENESIS_BLOCK_2026_ZERO_DATA_GATEWAY"

        if REDIS_AVAILABLE:
            try:
                self.redis_client = redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=1)
                self.redis_client.ping()
                if not self.redis_client.exists("audit:last_hash"):
                    self.redis_client.set("audit:last_hash", self.last_hash)
            except Exception:
                self.redis_client = None  # التراجع للذاكرة المحلية في حال عدم توفر Redis

    def append_record(self, tx_id: str, payload: Dict[str, Any], decision: str) -> str:
        timestamp = str(time.time())
        serialized_payload = json.dumps(payload, sort_keys=True)

        if self.redis_client:
            lua_script = """
            local last = redis.call('GET', 'audit:last_hash')
            local raw = last .. ARGV[1] .. ARGV[2] .. ARGV[3]
            local new_h = redis.sha1hex(raw)
            redis.call('SET', 'audit:last_hash', new_h)
            redis.call('RPUSH', 'audit:chain', cjson.encode({
                tx_id = ARGV[2],
                prev_hash = last,
                hash = new_h,
                timestamp = ARGV[3],
                decision = ARGV[4]
            }))
            return new_h
            """
            return self.redis_client.eval(lua_script, 0, serialized_payload, tx_id, timestamp, decision)

        # Fallback محلي في الذاكرة
        raw_data = f"{self.last_hash}{serialized_payload}{decision}{timestamp}".encode("utf-8")
        current_hash = hashlib.sha256(raw_data).hexdigest()
        self.chain.append({
            "tx_id": tx_id,
            "prev_hash": self.last_hash,
            "hash": current_hash,
            "timestamp": timestamp,
            "decision": decision
        })
        self.last_hash = current_hash
        return current_hash

# تهيئة السجل
ledger = HybridAuditLedger(redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"))

def evaluate_governance(payload: Dict[str, Any], policies: Dict[str, Any]) -> Dict[str, Any]:
    start_time = time.perf_counter()
    tx_id = payload.get("id", "UNKNOWN")
    opa_url = os.getenv("OPA_URL")

    # 1. التقييم المؤسسي عبر OPA Sidecar إن وُجد
    if opa_url and HTTPX_AVAILABLE:
        try:
            with httpx.Client(timeout=0.5) as client:
                res = client.post(f"{opa_url}/v1/data/governance/intent", json={"input": payload})
                if res.status_code == 200:
                    result = res.json().get("result", {})
                    if result.get("allow"):
                        latency = (time.perf_counter() - start_time) * 1000
                        audit_hash = ledger.append_record(tx_id, payload, "INTENT_LOCKED_OPA")
                        return {
                            "tx_id": tx_id,
                            "status": "INTENT_LOCKED",
                            "action": "EXECUTE_IMMEDIATELY",
                            "degrees_of_freedom": 0,
                            "latency_ms": round(latency, 4),
                            "tokens_consumed": 0,
                            "hallucination_risk": "0.0%",
                            "audit_hash": audit_hash,
                            "engine_source": "Open Policy Agent (Sidecar)"
                        }
                    elif result.get("disambiguation_required"):
                        latency = (time.perf_counter() - start_time) * 1000
                        audit_hash = ledger.append_record(tx_id, payload, "DISAMBIGUATION_REQUIRED_OPA")
                        return {
                            "tx_id": tx_id,
                            "status": "ACTIVE_DISAMBIGUATION_REQUIRED",
                            "action": "PROMPT_USER_FOR_MISSING_FIELD",
                            "degrees_of_freedom": 1,
                            "required_field": "budget_cleared",
                            "prompt_to_user": "Please confirm 'budget_cleared' approval to collapse state to DoF=0.",
                            "latency_ms": round(latency, 4),
                            "tokens_consumed": 0,
                            "hallucination_risk": "0.0% (Deterministic Probe)",
                            "audit_hash": audit_hash,
                            "engine_source": "Open Policy Agent (Sidecar)"
                        }
        except Exception:
            pass  # في حال تعثر OPA يتم الانتقال للمحرك الحتمي الداخلي

    # 2. التقييم الداخلي الحتمي (Deterministic Policy Engine)
    violations = []
    missing_parameters = []

    vendor_normalized = payload.get("vendor", "").strip().lower()
    approved_vendors_flat = [
        alias.lower()
        for aliases in policies.get("approved_vendors", {}).values()
        for alias in aliases
    ]

    if vendor_normalized not in approved_vendors_flat:
        violations.append("UNAUTHORIZED_VENDOR")

    if payload.get("department") not in policies.get("allowed_departments", []):
        violations.append("UNAUTHORIZED_DEPARTMENT")

    if payload.get("amount", 0.0) > policies.get("max_auto_approval_limit", 5000.0):
        violations.append("AMOUNT_EXCEEDS_THRESHOLD")

    if not payload.get("budget_cleared", False):
        missing_parameters.append("budget_cleared")

    dof = len(violations) + len(missing_parameters)
    latency = (time.perf_counter() - start_time) * 1000

    if dof == 0:
        audit_hash = ledger.append_record(tx_id, payload, "INTENT_LOCKED")
        return {
            "tx_id": tx_id,
            "status": "INTENT_LOCKED",
            "action": "EXECUTE_IMMEDIATELY",
            "degrees_of_freedom": 0,
            "state_collapsed": True,
            "latency_ms": round(latency, 4),
            "tokens_consumed": 0,
            "hallucination_risk": "0.0%",
            "audit_hash": audit_hash,
            "engine_source": "Deterministic Internal Engine"
        }
    elif dof == 1 and missing_parameters:
        audit_hash = ledger.append_record(tx_id, payload, "DISAMBIGUATION_REQUIRED")
        return {
            "tx_id": tx_id,
            "status": "ACTIVE_DISAMBIGUATION_REQUIRED",
            "action": "PROMPT_USER_FOR_MISSING_FIELD",
            "degrees_of_freedom": 1,
            "required_field": missing_parameters[0],
            "prompt_to_user": f"Transaction ambiguity detected: Please confirm if '{missing_parameters[0]}' is approved to collapse state to DoF=0.",
            "latency_ms": round(latency, 4),
            "tokens_consumed": 0,
            "hallucination_risk": "0.0% (Deterministic Probe)",
            "audit_hash": audit_hash,
            "engine_source": "Deterministic Internal Engine"
        }
    else:
        audit_hash = ledger.append_record(tx_id, payload, "HALTED_ARRESTING_HAZARD")
        return {
            "tx_id": tx_id,
            "status": "HALTED_ARRESTING_HAZARD",
            "action": "DETERMINISTIC_HALT (" + " | ".join(violations + [f"MISSING_{m.upper()}" for m in missing_parameters]) + ")",
            "degrees_of_freedom": dof,
            "state_collapsed": False,
            "latency_ms": round(latency, 4),
            "tokens_consumed": 0,
            "hallucination_risk": "0.0% (Risk Blocked)",
            "audit_hash": audit_hash,
            "engine_source": "Deterministic Internal Engine"
        }
