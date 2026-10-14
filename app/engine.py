import hashlib
import hmac
import json
import time
import os
from typing import Any, Dict, Iterable

# التحقق من وجود مكتبات الاتصال الموزع
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    redis = None
    REDIS_AVAILABLE = False

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


class PolicyEngineUnavailable(RuntimeError):
    pass


class AuditLedgerUnavailable(RuntimeError):
    pass


GENESIS_HASH = "GENESIS_BLOCK_2026_ZERO_DATA_GATEWAY"


def _canonical_json(value: Dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _build_audit_entry(
    tx_id: str,
    previous_hash: str,
    payload: Dict[str, Any],
    decision: str,
    timestamp: str,
) -> Dict[str, str]:
    envelope = {
        "tx_id": tx_id,
        "prev_hash": previous_hash,
        "payload_hash": hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest(),
        "decision": decision,
        "timestamp": timestamp,
    }
    return {
        **envelope,
        "hash": hashlib.sha256(_canonical_json(envelope).encode("utf-8")).hexdigest(),
    }


def verify_audit_chain(records: Iterable[Dict[str, str]]) -> bool:
    previous_hash = GENESIS_HASH
    for record in records:
        if set(record) != {
            "tx_id",
            "prev_hash",
            "payload_hash",
            "decision",
            "timestamp",
            "hash",
        }:
            return False
        if record.get("prev_hash") != previous_hash:
            return False
        envelope = {
            key: record.get(key)
            for key in ("tx_id", "prev_hash", "payload_hash", "decision", "timestamp")
        }
        if not all(isinstance(value, str) for value in envelope.values()):
            return False
        expected_hash = hashlib.sha256(_canonical_json(envelope).encode("utf-8")).hexdigest()
        if not isinstance(record.get("hash"), str) or not hmac.compare_digest(
            record["hash"], expected_hash
        ):
            return False
        previous_hash = expected_hash
    return True


class HybridAuditLedger:
    def __init__(self, redis_url: str | None = None):
        self.redis_client = None
        self.redis_required = redis_url is not None
        self.chain = []
        self.last_hash = GENESIS_HASH

        if self.redis_required and REDIS_AVAILABLE:
            try:
                self.redis_client = redis.from_url(
                    redis_url,
                    decode_responses=True,
                    socket_connect_timeout=1,
                    socket_timeout=1,
                )
                self.redis_client.ping()
                self.redis_client.setnx("audit:last_hash", self.last_hash)
            except Exception:
                self.redis_client = None

    def append_record(self, tx_id: str, payload: Dict[str, Any], decision: str) -> str:
        timestamp = str(time.time())

        if self.redis_required and self.redis_client is None:
            raise AuditLedgerUnavailable("Required Redis audit ledger is unavailable")

        if self.redis_client:
            for _ in range(5):
                try:
                    with self.redis_client.pipeline() as pipeline:
                        pipeline.watch("audit:last_hash")
                        previous_hash = pipeline.get("audit:last_hash")
                        if not previous_hash:
                            raise AuditLedgerUnavailable("Redis audit chain has no head hash")
                        entry = _build_audit_entry(
                            tx_id, previous_hash, payload, decision, timestamp
                        )
                        pipeline.multi()
                        pipeline.set("audit:last_hash", entry["hash"])
                        pipeline.rpush("audit:chain", _canonical_json(entry))
                        pipeline.execute()
                        return entry["hash"]
                except redis.WatchError:
                    continue
                except AuditLedgerUnavailable:
                    raise
                except Exception as exc:
                    if self.redis_required:
                        raise AuditLedgerUnavailable("Required Redis audit ledger is unavailable") from exc
                    raise
            raise AuditLedgerUnavailable("Redis audit chain update contention exceeded retries")

        entry = _build_audit_entry(tx_id, self.last_hash, payload, decision, timestamp)
        self.chain.append(entry)
        self.last_hash = entry["hash"]
        return entry["hash"]

# تهيئة السجل
ledger = HybridAuditLedger(redis_url=os.getenv("REDIS_URL"))

def evaluate_governance(payload: Dict[str, Any], policies: Dict[str, Any]) -> Dict[str, Any]:
    start_time = time.perf_counter()
    tx_id = payload.get("id", "UNKNOWN")
    opa_url = os.getenv("OPA_URL")

    # A configured OPA is authoritative; never fall back when it is unavailable.
    if opa_url:
        if not HTTPX_AVAILABLE:
            raise PolicyEngineUnavailable("OPA is configured but httpx is unavailable")
        try:
            with httpx.Client(timeout=0.5) as client:
                res = client.post(f"{opa_url}/v1/data/governance/intent", json={"input": payload})
                if res.status_code != 200:
                    raise PolicyEngineUnavailable(f"OPA returned HTTP {res.status_code}")
                result = res.json().get("result")
        except PolicyEngineUnavailable:
            raise
        except Exception as exc:
            raise PolicyEngineUnavailable("Configured OPA policy engine is unavailable") from exc

        if not isinstance(result, dict):
            result = {}
        if result.get("allow") is True:
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
        if result.get("disambiguation_required") is True:
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

        latency = (time.perf_counter() - start_time) * 1000
        audit_hash = ledger.append_record(tx_id, payload, "POLICY_DENIED_OPA")
        return {
            "tx_id": tx_id,
            "status": "HALTED_POLICY_DENIED",
            "action": "DENY_BY_DEFAULT",
            "degrees_of_freedom": None,
            "state_collapsed": False,
            "latency_ms": round(latency, 4),
            "tokens_consumed": 0,
            "hallucination_risk": "0.0% (Risk Blocked)",
            "audit_hash": audit_hash,
            "engine_source": "Open Policy Agent (Sidecar)"
        }

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
