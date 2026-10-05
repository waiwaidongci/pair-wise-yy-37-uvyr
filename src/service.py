from __future__ import annotations

from typing import Any, Dict, Optional

from .audit import utc_now
from .domain import (ConflictError, ensure_role, normalize_severity,
                     require_number, require_text)
from .ledger import EventLedger, classify_record_event
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, RECORD_ROLES, STATES,
                    VIEW_ROLES, completion_blockers, escalation_required,
                    priority_score, response_deadline_hours, role_for_transition,
                    validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository
        self.ledger = EventLedger(repository)

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str,
                    device_id: Optional[str] = None) -> Dict[str, Any]:
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
        device_id = require_text(device_id or actor, "device_id", 100)

        self.ledger.ensure_baseline()
        now = utc_now()
        item = {
            "id": None,
            "title": title, "description": description, "severity": severity,
            "quantity": quantity, "threshold": threshold, "status": STATES[0],
            "version": 1, "external_ref": external_ref, "created_by": actor,
            "created_at": now, "updated_at": now,
        }
        event = {
            "device_id": device_id,
            "event_type": "permit",
            "aggregate_type": "item",
            "aggregate_id": None,
            "payload": {
                "action": "created",
                "actor": actor,
                "item": item,
                "audit_detail": {
                    "title": title, "severity": severity, "quantity": quantity,
                    "priority": priority_score(severity, quantity, threshold),
                },
            },
        }
        result = self.ledger.submit([event])
        item_id = int(result["confirmed"][0]["aggregate_id"])
        return self.enrich(self.repository.get_item(item_id))

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str, device_id: Optional[str] = None) -> Dict[str, Any]:
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
        device_id = require_text(device_id or actor, "device_id", 100)

        self.ledger.ensure_baseline()
        self.repository.get_item(item_id)
        if external_ref is not None:
            dup = [r for r in self.repository.list_records(item_id)
                   if r.get("external_ref") == external_ref]
            if dup:
                raise ConflictError("记录唯一标识已存在")

        now = utc_now()
        record = {
            "id": None,
            "item_id": item_id,
            "kind": kind, "detail": detail, "status": status,
            "external_ref": external_ref, "created_by": actor, "created_at": now,
        }
        event_type = classify_record_event(kind)
        event = {
            "device_id": device_id,
            "event_type": event_type,
            "aggregate_type": "item",
            "aggregate_id": item_id,
            "payload": {
                "actor": actor,
                "record": record,
                "audit_detail": {"kind": kind, "status": status},
            },
        }
        result = self.ledger.submit([event])
        record_id = int(result["confirmed"][0]["payload"]["record"]["id"])
        return next(r for r in self.repository.list_records(item_id) if r["id"] == record_id)

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str, device_id: Optional[str] = None) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))
        device_id = require_text(device_id or actor, "device_id", 100)

        self.ledger.ensure_baseline()
        now = utc_now()
        event = {
            "device_id": device_id,
            "event_type": "permit",
            "aggregate_type": "item",
            "aggregate_id": item_id,
            "payload": {
                "action": "transitioned",
                "from": item["status"], "to": target, "actor": actor,
                "updated_at": now,
                "guard": {"version": expected_version},
                "audit_detail": {
                    "from": item["status"], "to": target,
                    "escalation_required": escalation_required(
                        item["severity"], item["quantity"], item["threshold"]),
                },
            },
        }
        self.ledger.submit([event])
        return self.enrich(self.repository.get_item(item_id))

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
