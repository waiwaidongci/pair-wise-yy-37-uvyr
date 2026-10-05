"""事件账测试：设备序号 + 因果序号、乱序补传、缺号停住、防篡改、恢复幂等、基线升级。"""
import json
import tempfile
import unittest
from pathlib import Path

from src.domain import ConflictError
from src.ledger import CausalGap, ConfirmedEventTampered, EventLedger
from src.repository import Repository
from src.service import Service


def _item_payload(title="test item", severity="low"):
    return {
        "title": title, "description": "desc", "severity": severity,
        "quantity": 1.0, "threshold": 10.0, "status": "draft", "version": 1,
        "external_ref": None, "created_by": "dev1",
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
    }


def _record_payload(kind="evidence", status="open"):
    return {
        "kind": kind, "detail": "detail", "status": status,
        "external_ref": None, "created_by": "dev1",
        "created_at": "2026-01-01T00:00:00+00:00",
    }


def _created(device_id, seq, title="test item"):
    return {"device_id": device_id, "device_seq": seq, "event_type": "permit",
            "aggregate_type": "item", "aggregate_id": None,
            "payload": {"action": "created", "item": _item_payload(title)}}


def _inspection(device_id, seq, item_id=1, kind="evidence"):
    return {"device_id": device_id, "device_seq": seq, "event_type": "inspection",
            "aggregate_type": "item", "aggregate_id": item_id,
            "payload": {"record": _record_payload(kind)}}


def _rectification(device_id, seq, item_id=1):
    return {"device_id": device_id, "device_seq": seq, "event_type": "rectification",
            "aggregate_type": "item", "aggregate_id": item_id,
            "payload": {"record": _record_payload("action", "closed")}}


class LedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.ledger = EventLedger(self.repo)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def test_out_of_order_rebuilds_by_causality(self):
        # 乱序补传：3,1,2 到达，按因果序 1,2,3 确认
        result = self.ledger.submit([
            _rectification("dev1", 3),
            _created("dev1", 1),
            _inspection("dev1", 2),
        ])
        self.assertEqual([e["device_seq"] for e in result["confirmed"]], [1, 2, 3])
        self.assertEqual(result["duplicates"], [])
        self.assertEqual(result["last_causal_seq"], 3)
        # 因果序号全局单调
        self.assertEqual([e["causal_seq"] for e in result["confirmed"]], [1, 2, 3])
        # 状态重建：1 个 item + 2 条记录
        item = self.repo.get_item(1)
        self.assertEqual(item["status"], "draft")
        recs = self.repo.list_records(1)
        self.assertEqual(len(recs), 2)
        self.assertEqual({r["kind"] for r in recs}, {"evidence", "action"})

    def test_gap_halts_and_preserves_result(self):
        self.ledger.submit([_created("dev1", 1)])
        # 缺号：期望 seq2，实际 seq3
        with self.assertRaises(CausalGap):
            self.ledger.submit([_inspection("dev1", 3)])
        # 原结果保留：仍只有 item，无记录
        self.assertEqual(len(self.repo.list_records(1)), 0)
        self.assertEqual(self.ledger.ledger_status()["confirmed"], 1)

    def test_tampered_confirmed_event_halts_and_preserves(self):
        self.ledger.submit([_created("dev1", 1, title="original")])
        # 改写已确认事件内容
        with self.assertRaises(ConfirmedEventTampered):
            self.ledger.submit([_created("dev1", 1, title="tampered")])
        # 原结果保留
        self.assertEqual(self.repo.get_item(1)["title"], "original")
        self.assertEqual(self.ledger.ledger_status()["confirmed"], 1)

    def test_idempotent_replay_no_duplicate_audit(self):
        self.ledger.submit([_created("dev1", 1)])
        audits_before = len(self.repo.list_audit())
        # 重放同一事件（内容一致）-> 幂等，不重复写审计
        result = self.ledger.submit([_created("dev1", 1)])
        self.assertEqual(len(result["duplicates"]), 1)
        self.assertEqual(len(result["confirmed"]), 0)
        self.assertEqual(len(self.repo.list_audit()), audits_before)

    def test_recover_from_last_confirmed_event(self):
        self.ledger.submit([_created("dev1", 1)])
        # 补传失败（缺号）
        with self.assertRaises(CausalGap):
            self.ledger.submit([_inspection("dev1", 3)])
        # 从最后确认事件恢复
        recovered = self.ledger.recover()
        self.assertEqual(recovered["status"], "recovered")
        self.assertEqual(len(recovered["state"]["records"]), 0)
        # 补齐缺号后重放，不重复
        result = self.ledger.submit([_inspection("dev1", 2)])
        self.assertEqual(len(result["confirmed"]), 1)
        self.assertEqual(len(result["duplicates"]), 0)
        recovered = self.ledger.recover()
        self.assertEqual(recovered["status"], "recovered")
        self.assertEqual(len(recovered["state"]["records"]), 1)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_recover_after_tamper_halts_preserves_snapshot(self):
        self.ledger.submit([_created("dev1", 1)])
        self.ledger.take_snapshot()
        # 直接篡改已确认事件载荷
        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute(
                "UPDATE ledger_events SET payload=? WHERE device_id=? AND device_seq=?",
                (json.dumps({"action": "created", "item": _item_payload("hacked")},
                            ensure_ascii=False, sort_keys=True), "dev1", 1))
        recovered = self.ledger.recover()
        self.assertEqual(recovered["status"], "halted")
        self.assertIn("改写", recovered["reason"])
        # 保留快照中的原结果
        self.assertEqual(recovered["state"]["items"][1]["title"], "test item")

    def test_baseline_upgrades_legacy_data(self):
        # 模拟旧数据：直接写 items/records（无事件）
        from src.audit import utc_now
        now = utc_now()
        with self.repo._lock, self.repo.conn:
            cur = self.repo.conn.execute(
                """INSERT INTO items(title, description, severity, quantity, threshold,
                   status, version, external_ref, created_by, created_at, updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                ("legacy item", "old", "high", 5.0, 10.0, "inspection", 3,
                 "LEG-1", "oldtimer", now, now))
            item_id = int(cur.lastrowid)
            self.repo.conn.execute(
                """INSERT INTO records(item_id, kind, detail, status, external_ref,
                   created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                (item_id, "inspection", "legacy finding", "open", "LEG-R1",
                 "oldtimer", now))
        # 旧数据升级为基线事件
        baselined = self.ledger.ensure_baseline()
        self.assertEqual(len(baselined), 1)
        self.assertEqual(baselined[0]["event_type"], "baseline")
        status = self.ledger.ledger_status()
        self.assertEqual(status["confirmed"], 1)
        # 状态保留
        item = self.repo.get_item(item_id)
        self.assertEqual(item["title"], "legacy item")
        self.assertEqual(item["status"], "inspection")
        self.assertEqual(len(self.repo.list_records(item_id)), 1)
        # 基线幂等：再次调用不重复
        self.assertEqual(self.ledger.ensure_baseline(), [])

    def test_multi_device_causal_ordering(self):
        # 两台设备同时提交，因果序号全局单调
        self.ledger.submit([_created("devA", 1)])
        self.ledger.submit([_inspection("devB", 1, item_id=1)])
        self.ledger.submit([_rectification("devA", 2, item_id=1)])
        status = self.ledger.ledger_status()
        self.assertEqual(status["confirmed"], 3)
        self.assertEqual(status["last_causal_seq"], 3)
        self.assertEqual(set(status["devices"]), {"devA", "devB"})
        # 状态正确
        self.assertEqual(len(self.repo.list_records(1)), 2)

    def test_three_event_types_distinct(self):
        self.ledger.submit([_created("dev1", 1)])
        self.ledger.submit([_inspection("dev1", 2, kind="evidence")])
        self.ledger.submit([_rectification("dev1", 3)])
        events = self.ledger._load_confirmed_events()
        types = [e["event_type"] for e in events]
        self.assertEqual(types, ["permit", "inspection", "rectification"])
        self.assertEqual(len(self.repo.list_records(1)), 2)

    def test_service_routes_through_ledger(self):
        svc = Service(self.repo)
        item = svc.create_item({"title": "svc item", "description": "d",
                                "severity": "high", "quantity": 12, "threshold": 6},
                               "creator", "applicant", device_id="dev1")
        self.assertEqual(item["status"], "draft")
        svc.add_record(item["id"], {"kind": "evidence", "detail": "finding", "status": "closed"},
                       "inspector", "inspector", device_id="dev1")
        current = item
        from src.rules import STATES, TRANSITION_ROLES
        for target in STATES[1:]:
            current = svc.transition(current["id"], target, current["version"],
                                     "reviewer", TRANSITION_ROLES[target][0], device_id="dev1")
        self.assertEqual(current["status"], "approved")
        self.assertEqual(len(svc.list_records(current["id"], "viewer")), 1)
        self.assertTrue(self.repo.verify_audit_chain())
        # 审计与事件一一对应（重放不重复）
        audits = svc.audit("viewer")
        self.assertEqual(len(audits), 6)


if __name__ == "__main__":
    unittest.main()
