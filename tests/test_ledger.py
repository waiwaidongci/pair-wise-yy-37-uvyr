import tempfile
import unittest
from pathlib import Path

from src.domain import (LedgerForkError, LedgerGapError, LedgerTamperError,
                        PermissionDenied, ValidationError)
from src.ledger import (INSPECTION, LICENSE, RECTIFICATION, event_key,
                        order_by_causality, plan_backfill, rebuild_state)
from src.repository import Repository
from src.service import Service


def ev(device_id, seq, event_type, payload, causal_prev=None, item_id=1):
    return {"item_id": item_id, "device_id": device_id, "device_seq": seq,
            "causal_prev": causal_prev, "type": event_type, "payload": payload,
            "event_key": event_key(device_id, seq)}


class CausalityLogicTest(unittest.TestCase):
    def test_out_of_order_rebuild_by_causality(self):
        # 两台设备，序号交错，按因果关系而非写入顺序重建
        a1 = ev("devA", 1, LICENSE, {"license_no": "L-1", "action": "grant"}, None)
        b1 = ev("devB", 1, INSPECTION,
                {"finding": "ok", "severity": "low"}, "devA#1")
        a2 = ev("devA", 2, RECTIFICATION,
                {"rectification_id": "R-1", "action": "open",
                 "resolution": ""}, "devB#1")
        b2 = ev("devB", 2, RECTIFICATION,
                {"rectification_id": "R-1", "action": "close",
                 "resolution": "done"}, "devA#2")
        state = rebuild_state([b2, a2, b1, a1])  # 故意乱序
        self.assertEqual(state["head"], "devB#2")
        self.assertEqual(state["license"]["license_no"], "L-1")
        self.assertEqual(state["inspection"]["finding"], "ok")
        self.assertEqual(state["open_rectifications"], {})  # 已关闭

    def test_missing_causal_prev_stops(self):
        a2 = ev("devA", 2, INSPECTION,
                {"finding": "x", "severity": "low"}, "devA#1")
        # 设备序号缺 1 号；规划补传时必须停住
        with self.assertRaises(LedgerGapError):
            plan_backfill([a2], [], None)
        # 因果前驱在批次外也无法解析
        with self.assertRaises(LedgerGapError):
            plan_backfill([ev("devA", 1, INSPECTION,
                              {"finding": "x", "severity": "low"}, "devZ#9")],
                          [], None)

    def test_fork_rejected_in_rebuild(self):
        a1 = ev("devA", 1, LICENSE,
                {"license_no": "L", "action": "grant"}, None)
        b1 = ev("devB", 1, INSPECTION,
                {"finding": "one", "severity": "low"}, "devA#1")
        c1 = ev("devC", 1, INSPECTION,
                {"finding": "two", "severity": "high"}, "devA#1")
        with self.assertRaises(LedgerForkError):
            order_by_causality([a1, b1, c1])

    def test_backfill_plan_rejects_gap_and_fork_and_accepts_replay(self):
        a1 = ev("devA", 1, LICENSE,
                {"license_no": "L-1", "action": "grant"}, None)
        # 已确认历史：devA#1
        stored = [dict(a1, confirmed=True, previous_hash="GENESIS",
                       entry_hash="x", created_at="t", actor="s")]
        # 缺号：只补 devA#3，缺 devA#2
        with self.assertRaises(LedgerGapError):
            plan_backfill([ev("devA", 3, INSPECTION,
                              {"finding": "g", "severity": "low"}, "devA#1")],
                          stored, "devA#1")
        # 分叉：后继不接当前链头
        with self.assertRaises(LedgerForkError):
            plan_backfill([ev("devB", 1, INSPECTION,
                              {"finding": "late", "severity": "high"}, None)],
                          stored, "devA#1")
        # 整批重放：内容一致 -> 空计划，不重复写
        self.assertEqual(plan_backfill([a1], stored, "devA#1"), [])

    def test_tamper_with_confirmed_event_detected(self):
        a1 = ev("devA", 1, LICENSE,
                {"license_no": "L-1", "action": "grant"}, None)
        changed = dict(a1, payload={"license_no": "L-2", "action": "grant"})
        stored = [dict(a1, confirmed=True, previous_hash="GENESIS",
                       entry_hash="x", created_at="t", actor="s")]
        with self.assertRaises(LedgerTamperError):
            plan_backfill([changed], stored, "devA#1")


class LedgerServiceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.item = self.service.create_item(
            {"title": "ledger item", "description": "event sourcing",
             "severity": "high", "quantity": 5, "threshold": 10,
             "external_ref": "LED-1"}, "creator", "applicant")
        self.iid = self.item["id"]

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _license(self, device="devA", seq=1, prev=None,
                 action="grant", no="L-1"):
        return self.service.submit_change(
            self.iid, LICENSE,
            {"device_id": device, "device_seq": seq, "causal_prev": prev,
             "payload": {"license_no": no, "action": action}},
            "officer", "applicant")

    def test_three_change_types_in_one_causal_chain(self):
        self._license()
        insp = self.service.submit_change(
            self.iid, INSPECTION,
            {"device_id": "devB", "device_seq": 1,
             "payload": {"finding": "dust超标", "severity": "high"}},
            "inspector1", "inspector")
        self.assertTrue(insp["confirmed"])
        rect = self.service.submit_change(
            self.iid, RECTIFICATION,
            {"device_id": "devB", "device_seq": 2,
             "payload": {"rectification_id": "R-1", "action": "open",
                         "resolution": ""}},
            "inspector1", "inspector")
        self.assertTrue(rect["confirmed"])
        state = self.service.ledger_state(self.iid, "viewer")
        self.assertEqual(state["state"]["head"], "devB#2")
        self.assertEqual(state["pending"], 0)
        self.assertIn("R-1", state["state"]["open_rectifications"])
        self.assertTrue(self.service.verify_ledger(self.iid, "viewer")["verified"])

    def test_two_inspectors_concurrent_late_submit_does_not_overwrite(self):
        self._license()
        head = event_key("devA", 1)
        payload = {"finding": "first confirmed", "severity": "low"}
        first = self.service.submit_change(
            self.iid, INSPECTION,
            {"device_id": "devB", "device_seq": 1, "causal_prev": head,
             "payload": payload}, "inspector1", "inspector")
        self.assertTrue(first["confirmed"])
        # 晚到的检查员同样基于旧链头提交 -> 因果序号冲突
        with self.assertRaises(LedgerForkError):
            self.service.submit_change(
                self.iid, INSPECTION,
                {"device_id": "devC", "device_seq": 1, "causal_prev": head,
                 "payload": {"finding": "late overwrite", "severity": "critical"}},
                "inspector2", "inspector")
        state = self.service.ledger_state(self.iid, "viewer")
        # 先确认的结果保留
        self.assertEqual(state["state"]["inspection"]["finding"],
                         "first confirmed")

    def test_power_loss_replay_is_idempotent(self):
        self._license()
        before = len(self.service.audit("viewer", self.iid))
        # 设备断电重放：同一设备序号原样重发（含首次的因果序号）
        again = self.service.submit_change(
            self.iid, LICENSE,
            {"device_id": "devA", "device_seq": 1, "causal_prev": None,
             "payload": {"action": "grant", "license_no": "L-1"}},
            "officer", "applicant")
        self.assertTrue(again["confirmed"])
        after = len(self.service.audit("viewer", self.iid))
        self.assertEqual(before, after)  # 审计不重复写
        events = self.repo.list_ledger_events(self.iid)
        self.assertEqual(len([e for e in events if e["type"] == LICENSE]), 1)

    def test_out_of_order_parks_then_drains_when_predecessor_arrives(self):
        self._license()  # head devA#1
        # 先发 devB#2，前驱 devB#1 未到 -> 停放，当前结果不变
        result = self.service.backfill_changes(
            self.iid,
            {"accept_pending": True,
             "events": [
                {"device_id": "devB", "device_seq": 2,
                 "causal_prev": "devB#1", "type": INSPECTION,
                 "payload": {"finding": "future", "severity": "medium"}}]},
            "inspector1", "inspector")
        self.assertEqual(result["parked"], 1)
        state = self.service.ledger_state(self.iid, "viewer")
        self.assertEqual(state["pending"], 1)
        self.assertIsNone(state["state"]["inspection"])
        # 补传缺的 devB#1 -> 链自动贯通，停放事件确认
        result = self.service.backfill_changes(
            self.iid,
            {"events": [
                {"device_id": "devB", "device_seq": 1,
                 "causal_prev": "devA#1", "type": INSPECTION,
                 "payload": {"finding": "first", "severity": "low"}}]},
            "inspector1", "inspector")
        self.assertEqual(result["inserted"], 1)
        state = self.service.ledger_state(self.iid, "viewer")
        self.assertEqual(state["pending"], 0)
        self.assertEqual(state["state"]["head"], "devB#2")
        self.assertEqual(state["state"]["inspection"]["finding"], "future")

    def test_backfill_gap_keeps_original_result(self):
        self._license()
        with self.assertRaises(LedgerGapError):
            self.service.backfill_changes(
                self.iid,
                {"events": [
                    {"device_id": "devB", "device_seq": 2,
                     "causal_prev": "devA#1", "type": INSPECTION,
                     "payload": {"finding": "gapped", "severity": "low"}}]},
                "inspector1", "inspector")
        # 原结果保留：链头仍是 devA#1，没有部分写入
        cp = self.repo.get_checkpoint(self.iid)
        self.assertEqual(cp["head_key"], "devA#1")
        self.assertEqual(self.repo.list_ledger_events(self.iid,
                                                      confirmed=True).__len__(), 1)

    def test_tamper_confirmed_event_stops_and_preserves(self):
        self._license()
        original = self.repo.list_ledger_events(self.iid)[0]
        # 直接在库内篡改已确认事件内容（不改哈希），并提交
        import json as _json
        with self.repo.conn:
            self.repo.conn.execute(
                "UPDATE ledger_events SET payload=? WHERE id=?",
                (_json.dumps({"license_no": "FORGED", "action": "revoke"},
                             ensure_ascii=False, sort_keys=True),
                 original["id"]))
        with self.assertRaises(LedgerTamperError):
            self.service.recover(self.iid, "inspector1", "inspector")
        with self.assertRaises(LedgerTamperError):
            self.service.verify_ledger(self.iid, "viewer")

    def test_recover_after_failed_backfill_restores_last_confirmed(self):
        self._license()
        # 停放一个无法接续的乱序事件（前驱永远不会到达）
        self.repo.park_pending_event(
            self.iid, INSPECTION, "devB", 5, "devB#4",
            {"finding": "orphan", "severity": "low"}, "inspector1")
        self.assertEqual(self.service.ledger_state(self.iid, "viewer")["pending"], 1)
        result = self.service.recover(self.iid, "inspector1", "inspector")
        self.assertEqual(result["head_key"], "devA#1")
        self.assertEqual(result["discarded_pending"], 1)
        self.assertEqual(self.service.ledger_state(self.iid, "viewer")["pending"], 0)

    def test_replay_after_recovery_does_not_duplicate_audit(self):
        self._license()
        before = len(self.service.audit("viewer", self.iid))
        result = self.service.backfill_changes(
            self.iid,
            {"events": [
                {"device_id": "devA", "device_seq": 1,
                 "causal_prev": None, "type": LICENSE,
                 "payload": {"license_no": "L-1", "action": "grant"}}]},
            "officer", "applicant")
        self.assertEqual(result["inserted"], 0)
        self.assertEqual(result["replayed"], 1)
        self.assertEqual(len(self.service.audit("viewer", self.iid)), before)

    def test_role_guard_for_change_types(self):
        with self.assertRaises(PermissionDenied):
            self.service.submit_change(
                self.iid, INSPECTION,
                {"device_id": "d", "device_seq": 1,
                 "payload": {"finding": "x", "severity": "low"}},
                "evil", "applicant")

    def test_invalid_shape_rejected(self):
        with self.assertRaises(ValidationError):
            self.service.submit_change(
                self.iid, INSPECTION,
                {"device_id": "d", "device_seq": 0,
                 "payload": {"finding": "x", "severity": "low"}},
                "i", "inspector")


class LegacyBaselineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def test_legacy_data_upgraded_to_baseline(self):
        item = self.service.create_item(
            {"title": "old item", "description": "pre-ledger data",
             "severity": "medium", "quantity": 1, "threshold": 2,
             "external_ref": "OLD-1"}, "creator", "applicant")
        self.service.add_record(
            item["id"],
            {"kind": "rectification", "detail": "待整改", "status": "open",
             "external_ref": "RECT-9"}, "recorder", "applicant")
        upgraded = self.repo.upgrade_legacy_baseline()
        self.assertEqual(upgraded, [item["id"]])
        # 升级幂等：再次执行不产生第二条基线
        self.assertEqual(self.repo.upgrade_legacy_baseline(), [])
        state = self.service.ledger_state(item["id"], "viewer")
        self.assertIsNotNone(state["state"]["license"])
        self.assertIn("RECT-9", state["state"]["open_rectifications"])
        # 基线是链根，新事件接在基线之后
        evt = self.service.submit_change(
            item["id"], INSPECTION,
            {"device_id": "devA", "device_seq": 1,
             "payload": {"finding": "post-upgrade", "severity": "low"}},
            "inspector1", "inspector")
        self.assertTrue(evt["confirmed"])
        self.assertEqual(evt["causal_prev"], f"legacy#baseline-{item['id']}")
        self.assertTrue(self.service.verify_ledger(item["id"], "viewer")["verified"])


if __name__ == "__main__":
    unittest.main()
