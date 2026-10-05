from __future__ import annotations

from typing import Any, Dict, Optional

from . import ledger
from .domain import (ensure_role, normalize_severity, require_number,
                     require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, RECORD_ROLES, TITLE,
                    VIEW_ROLES, completion_blockers, escalation_required,
                    priority_score, response_deadline_hours, role_for_transition,
                    validate_transition)

# 三类变更各自允许的提交角色
LEDGER_SUBMIT_ROLES = {
    ledger.LICENSE: {"applicant", "compliance_manager"},
    ledger.INSPECTION: {"inspector"},
    ledger.RECTIFICATION: {"inspector", "applicant"},
}


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority_score(severity, quantity, threshold),
        })
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        })
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            from .domain import ConflictError
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        })
        return self.enrich(updated)

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    # ------------------------------------------------------------------
    # 设备序号 + 因果序号事件账
    # ------------------------------------------------------------------
    def _ledger_payload(self, event_type: str,
                        payload: Dict[str, Any]) -> Dict[str, Any]:
        detail = payload.get("payload")
        if not isinstance(detail, dict):
            from .domain import ValidationError
            raise ValidationError("payload必须是事件内容对象")
        return detail

    def submit_change(self, item_id: int, event_type: str, payload: Dict[str, Any],
                      actor: str, role: str) -> Dict[str, Any]:
        """在线提交三类变更之一。

        必须携带设备序号 ``device_id``/``device_seq`` 与因果序号 ``causal_prev``。
        省略 ``causal_prev`` 时默认接在当前已确认链头之后（乐观提交）：
        两名检查员同时提交时，只有一人的因果序号能接上链头，晚到者收到冲突，
        已确认结果不会被覆盖。
        """
        from .domain import ValidationError
        ensure_role(role, LEDGER_SUBMIT_ROLES.get(event_type, set()))
        actor = require_text(actor, "actor", 100)
        device_id = require_text(payload.get("device_id"), "device_id", 100)
        device_seq = payload.get("device_seq")
        body = self._ledger_payload(event_type, payload)
        # 缺省（未提供该字段）时接当前链头；显式 null 表示根事件，须原样保留，
        # 否则设备重放根事件时会被误改写成“接当前链头”
        causal_prev = payload["causal_prev"] if "causal_prev" in payload \
            else self.repository.get_checkpoint(item_id)["head_key"]
        ledger.validate_event(event_type, device_id, device_seq, causal_prev, body)
        return self.repository.append_ledger_event(
            item_id, event_type, device_id, device_seq, causal_prev, body, actor)

    def backfill_changes(self, item_id: int, payload: Dict[str, Any],
                         actor: str, role: str) -> Dict[str, Any]:
        """乱序补传：按因果关系重建。

        缺号、改过已确认事件、非链头后继的分支都会停住并保留原结果
        （整批不写入）；纯重放批次返回 inserted=0 且不重复写审计。
        """
        ensure_role(role, VIEW_ROLES)
        require_text(actor, "actor", 100)
        events = payload.get("events")
        if not isinstance(events, list) or not events:
            from .domain import ValidationError
            raise ValidationError("events必须是非空数组")
        normalized = []
        for raw in events:
            if not isinstance(raw, dict):
                from .domain import ValidationError
                raise ValidationError("每个事件必须是对象")
            body = raw.get("payload", {})
            ledger.validate_event(raw.get("type"), raw.get("device_id"),
                                  raw.get("device_seq"), raw.get("causal_prev"),
                                  body)
            normalized.append({
                "item_id": item_id,
                "type": raw["type"], "device_id": raw["device_id"].strip(),
                "device_seq": raw["device_seq"],
                "causal_prev": (raw["causal_prev"].strip()
                                if isinstance(raw.get("causal_prev"), str)
                                else raw.get("causal_prev")),
                "payload": body, "actor": actor,
            })
        cp = self.repository.get_checkpoint(item_id)
        stored = self.repository.list_ledger_events(item_id)
        accept_pending = bool(payload.get("accept_pending", False))
        if accept_pending:
            # 断网现场模式：允许事件先停放，等前驱补传到达后自动贯通。
            # 分叉/篡改在规划阶段仍然拒绝；停放仅限因果前驱未到。
            confirmable, parkable = ledger.plan_pending(
                normalized, stored, cp["head_key"])
            replayed = len(normalized) - len(confirmable) - len(parkable)
            inserted = self.repository.backfill_ledger_events(
                item_id, confirmable)["inserted"] if confirmable else 0
            parked = 0
            for event in parkable:
                result_evt = self.repository.park_pending_event(
                    item_id, event["type"], event["device_id"],
                    event["device_seq"], event["causal_prev"],
                    event["payload"], actor)
                if not result_evt["confirmed"]:
                    parked += 1
            return {"inserted": inserted, "parked": parked,
                    "replayed": replayed,
                    "checkpoint": self.repository.get_checkpoint(item_id)}
        ordered = ledger.plan_backfill(normalized, stored, cp["head_key"])
        if not ordered:
            return {"inserted": 0, "replayed": len(normalized),
                    "checkpoint": cp}
        result = self.repository.backfill_ledger_events(item_id, ordered)
        result["replayed"] = len(normalized) - len(ordered)
        return result

    def recover(self, item_id: int, actor: str, role: str) -> Dict[str, Any]:
        """补传失败后：从最后确认事件恢复，丢弃未确认停放事件，重放不重复。"""
        ensure_role(role, VIEW_ROLES)
        require_text(actor, "actor", 100)
        return self.repository.recover_ledger(item_id)

    def ledger_state(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.repository.ledger_state(item_id)

    def verify_ledger(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        ok = self.repository.verify_ledger(item_id)
        return {"verified": ok}

    def upgrade_legacy(self, role: str) -> Dict[str, Any]:
        """旧数据升级成基线事件（通常启动时自动执行一次）。"""
        ensure_role(role, {"compliance_manager"})
        return {"upgraded_item_ids": self.repository.upgrade_legacy_baseline()}

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result
