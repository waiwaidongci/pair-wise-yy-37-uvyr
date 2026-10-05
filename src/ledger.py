"""事件账：带设备序号与因果序号的追加式事件日志。

本模块把许可(permit)、现场检查(inspection)、整改(rectification)三类变更
统一成带设备序号(device_id + device_seq)与因果序号(causal_seq)的事件，
旧数据通过基线事件(baseline)升级为事件账起点。

不变量：
- 幂等：(device_id, device_seq) 唯一；重放同一事件不重复写审计、不重复改状态。
- 因果：每个事件带全局单调 causal_seq，状态按 causal_seq 顺序折叠重建；
  乱序补传按因果序归位。
- 缺号：设备序号断裂（缺号）时停住，不应用断裂点之后的事件，保留最后确认结果。
- 防篡改：已确认事件内容被改写（payload_hash 变化）时停住，原结果保留。
- 恢复：补传失败后从最后确认事件恢复；重放不重复。
- 基线：旧数据升级为基线事件，作为事件账起点。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, ValidationError
from .rules import ENTITY


GENESIS = "GENESIS"
EVENT_TYPES = ("permit", "inspection", "rectification", "baseline")
# 记录 kind -> 事件类型：整改类归 rectification，其余现场检查归 inspection
_RECTIFICATION_KINDS = {"rectification", "correction", "action", "fix", "整改"}


class ConfirmedEventTampered(ConflictError):
    """已确认事件被改写：内容哈希与原确认结果不一致。"""


class CausalGap(ConflictError):
    """因果序号断裂：存在缺号，无法继续折叠。"""


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def payload_hash(payload: Dict[str, Any]) -> str:
    return _sha256(_canonical(payload))


def compute_event_hash(previous_hash: str, device_id: str, device_seq: int,
                       causal_seq: int, event_type: str, aggregate_type: str,
                       aggregate_id: int, phash: str, created_at: str) -> str:
    body = _canonical({
        "device_id": device_id, "device_seq": device_seq, "causal_seq": causal_seq,
        "event_type": event_type, "aggregate_type": aggregate_type,
        "aggregate_id": aggregate_id, "payload_hash": phash, "created_at": created_at,
    })
    return _sha256((previous_hash + ":").encode("utf-8") + body)


def classify_record_event(kind: str) -> str:
    return "rectification" if str(kind).strip().lower() in _RECTIFICATION_KINDS else "inspection"


class EventLedger:
    def __init__(self, repository):
        self.repo = repository
        self.conn = repository.conn
        self._lock = repository._lock
        self._create_schema()

    # ---------- schema ----------
    def _create_schema(self) -> None:
        with self._lock, self.conn:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS ledger_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    device_seq INTEGER NOT NULL,
                    causal_seq INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    aggregate_type TEXT NOT NULL DEFAULT 'item',
                    aggregate_id INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE,
                    confirmed INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    UNIQUE(device_id, device_seq),
                    UNIQUE(causal_seq)
                );
                CREATE TABLE IF NOT EXISTS ledger_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    causal_seq INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    state_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_ledger_aggregate
                    ON ledger_events(aggregate_type, aggregate_id, causal_seq);
            """)

    # ---------- helpers ----------
    def _next_table_id(self, table: str) -> int:
        row = self.conn.execute(f"SELECT COALESCE(MAX(id),0)+1 AS n FROM {table}").fetchone()
        return int(row["n"])

    def _max_confirmed_device_seq(self, device_id: str) -> int:
        row = self.conn.execute(
            "SELECT COALESCE(MAX(device_seq),0) AS m FROM ledger_events WHERE device_id=?",
            (device_id,)).fetchone()
        return int(row["m"])

    def next_device_seq(self, device_id: str) -> int:
        with self._lock:
            return self._max_confirmed_device_seq(device_id) + 1

    def _next_causal_seq(self) -> int:
        row = self.conn.execute(
            "SELECT COALESCE(MAX(causal_seq),0) AS m FROM ledger_events WHERE confirmed=1"
        ).fetchone()
        return int(row["m"]) + 1

    def _last_event_hash(self) -> str:
        row = self.conn.execute(
            "SELECT event_hash FROM ledger_events WHERE confirmed=1 ORDER BY causal_seq DESC LIMIT 1"
        ).fetchone()
        return row["event_hash"] if row else GENESIS

    def _last_causal_seq(self) -> int:
        row = self.conn.execute(
            "SELECT COALESCE(MAX(causal_seq),0) AS m FROM ledger_events WHERE confirmed=1"
        ).fetchone()
        return int(row["m"])

    # ---------- submit ----------
    def submit(self, events) -> Dict[str, Any]:
        """提交一批事件（补传）。

        批内事件按 (device_id, device_seq) 排序后确认，乱序自动归位；
        缺号或已确认事件被改写时停住（抛异常），不应用断裂点之后的事件。
        重放同一事件（device_id+device_seq 相同且内容一致）不重复写审计、不重复改状态。
        """
        if isinstance(events, dict):
            events = [events]
        if not events:
            return {"confirmed": [], "duplicates": [], "last_causal_seq": self._last_causal_seq()}

        prepared: List[Dict[str, Any]] = []
        for ev in events:
            device_id = str(ev["device_id"])
            event_type = str(ev["event_type"])
            if event_type not in EVENT_TYPES:
                raise ValidationError(f"未知事件类型 {event_type}")
            aggregate_type = str(ev.get("aggregate_type", "item"))
            aggregate_id = ev.get("aggregate_id")
            aggregate_id = int(aggregate_id) if aggregate_id is not None else None
            payload = ev.get("payload") or {}
            if not isinstance(payload, dict):
                raise ValidationError("payload必须是JSON对象")
            prepared.append({
                "device_id": device_id,
                "device_seq": ev.get("device_seq"),
                "event_type": event_type,
                "aggregate_type": aggregate_type,
                "aggregate_id": aggregate_id,
                "payload": payload,
            })

        # 自动补 device_seq（按设备分组，组内排序后连续分配）
        by_device: Dict[str, List[Dict[str, Any]]] = {}
        for p in prepared:
            by_device.setdefault(p["device_id"], []).append(p)
        for device_id, lst in by_device.items():
            lst.sort(key=lambda x: (x["device_seq"] is None,
                                    x["device_seq"] if x["device_seq"] is not None else 0))
            next_seq = self._max_confirmed_device_seq(device_id) + 1
            for p in lst:
                if p["device_seq"] is None:
                    p["device_seq"] = next_seq
                    next_seq += 1

        with self._lock, self.conn:
            item_counter = self._next_table_id("items")
            record_counter = self._next_table_id("records")
            # 先查幂等：已存在的事件复用其 id（重放不重复分配），新事件才分配 id
            for p in prepared:
                row = self.conn.execute(
                    "SELECT * FROM ledger_events WHERE device_id=? AND device_seq=?",
                    (p["device_id"], p["device_seq"])).fetchone()
                p["_existing"] = row
                if row is not None:
                    # 复用已确认事件的 id，保证重放幂等、不撞号
                    p["aggregate_id"] = int(row["aggregate_id"])
                    stored_payload = json.loads(row["payload"])
                    if p["event_type"] == "permit" and p["payload"].get("action") == "created":
                        p["payload"].setdefault("item", {})
                        p["payload"]["item"]["id"] = int(row["aggregate_id"])
                    if p["event_type"] in ("inspection", "rectification"):
                        p["payload"].setdefault("record", {})
                        stored_rec = stored_payload.get("record") or {}
                        if "id" in stored_rec:
                            p["payload"]["record"]["id"] = int(stored_rec["id"])
                        else:
                            p["payload"]["record"]["id"] = record_counter
                            record_counter += 1
                else:
                    if p["aggregate_id"] is None:
                        p["aggregate_id"] = item_counter
                        item_counter += 1
                    if p["event_type"] == "permit" and p["payload"].get("action") == "created":
                        p["payload"].setdefault("item", {})
                        p["payload"]["item"]["id"] = p["aggregate_id"]
                    if p["event_type"] in ("inspection", "rectification"):
                        p["payload"].setdefault("record", {})
                        p["payload"]["record"]["id"] = record_counter
                        record_counter += 1

            # 计算 payload_hash（id 确定后再算，保证哈希与存储一致）
            for p in prepared:
                p["payload_hash"] = payload_hash(p["payload"])

            # 幂等 + 防篡改检查
            confirmed_out: List[Dict[str, Any]] = []
            duplicates: List[Dict[str, Any]] = []
            for p in prepared:
                row = p["_existing"]
                if row is not None:
                    same = (row["payload_hash"] == p["payload_hash"]
                            and row["event_type"] == p["event_type"]
                            and int(row["aggregate_id"]) == p["aggregate_id"])
                    if same:
                        duplicates.append({
                            "device_id": p["device_id"], "device_seq": p["device_seq"],
                            "event_hash": row["event_hash"], "causal_seq": row["causal_seq"],
                        })
                        continue
                    raise ConfirmedEventTampered(
                        f"已确认事件被改写：{p['device_id']}#{p['device_seq']}，停住并保留原结果")
                confirmed_out.append(p)

            # 缺号检查：每个设备的新 seq 必须连续（乱序已在前面排序归位）
            new_by_device: Dict[str, List[int]] = {}
            for p in confirmed_out:
                new_by_device.setdefault(p["device_id"], []).append(p["device_seq"])
            for device_id, seqs in new_by_device.items():
                seqs.sort()
                expected = self._max_confirmed_device_seq(device_id) + 1
                for s in seqs:
                    if s != expected:
                        raise CausalGap(
                            f"因果缺号：{device_id} 期望 {expected} 实际 {s}，停住并保留最后确认结果")
                    expected += 1

            # 乐观锁守卫：permit/transitioned 携带 guard.version，
            # 在锁内核对当前物化版本，防止晚到的版本盖掉已确认结果。
            for p in confirmed_out:
                if p["event_type"] == "permit" and p["payload"].get("action") == "transitioned":
                    guard = p["payload"].get("guard") or {}
                    if "version" in guard:
                        row = self.conn.execute(
                            "SELECT version FROM items WHERE id=?", (p["aggregate_id"],)
                        ).fetchone()
                        current = int(row["version"]) if row else 1
                        if int(guard["version"]) != current:
                            raise ConflictError(
                                f"版本冲突：期望 {guard['version']} 实际 {current}，请刷新后重试")

            # 追加确认事件（causal_seq 全局单调）
            now = utc_now()
            last_hash = self._last_event_hash()
            for p in sorted(confirmed_out, key=lambda x: (x["device_id"], x["device_seq"])):
                causal = self._next_causal_seq()
                eh = compute_event_hash(
                    last_hash, p["device_id"], p["device_seq"], causal, p["event_type"],
                    p["aggregate_type"], p["aggregate_id"], p["payload_hash"], now)
                self.conn.execute(
                    """INSERT INTO ledger_events(device_id, device_seq, causal_seq, event_type,
                       aggregate_type, aggregate_id, payload, payload_hash, previous_hash,
                       event_hash, confirmed, created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,1,?)""",
                    (p["device_id"], p["device_seq"], causal, p["event_type"],
                     p["aggregate_type"], p["aggregate_id"],
                     json.dumps(p["payload"], ensure_ascii=False, sort_keys=True),
                     p["payload_hash"], last_hash, eh, now))
                p["causal_seq"] = causal
                p["event_hash"] = eh
                p["created_at"] = now
                last_hash = eh

            # 折叠重建物化状态（items/records），保证与事件账一致
            state = self._fold(self._load_confirmed_events())
            self._materialize(state)

            # 为每个新确认事件写一条审计（幂等：重放事件已在前面去重，不会重复写）
            for p in confirmed_out:
                self._append_audit_for_event(p)

        confirmed_sorted = sorted(confirmed_out, key=lambda x: x["causal_seq"])
        for p in confirmed_sorted:
            p.pop("_existing", None)
        return {"confirmed": confirmed_sorted, "duplicates": duplicates,
                "last_causal_seq": self._last_causal_seq()}

    # ---------- 折叠与物化 ----------
    def _load_confirmed_events(self) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM ledger_events WHERE confirmed=1 ORDER BY causal_seq"
        ).fetchall()
        out = []
        for row in rows:
            d = dict(row)
            d["payload"] = json.loads(d["payload"])
            out.append(d)
        return out

    def _fold(self, events: List[Dict[str, Any]]) -> Dict[str, Dict[int, Dict[str, Any]]]:
        items: Dict[int, Dict[str, Any]] = {}
        records: Dict[int, Dict[str, Any]] = {}
        for ev in events:
            et = ev["event_type"]
            payload = ev["payload"]
            if et == "baseline":
                item = payload["item"]
                items[item["id"]] = dict(item)
                for rec in payload.get("records", []):
                    records[rec["id"]] = dict(rec)
            elif et == "permit":
                action = payload.get("action")
                if action == "created":
                    item = dict(payload["item"])
                    item["id"] = ev["aggregate_id"]
                    items[item["id"]] = item
                elif action == "transitioned":
                    item = items.get(ev["aggregate_id"])
                    if item is None:
                        item = dict(payload.get("item", {}))
                        item.setdefault("id", ev["aggregate_id"])
                        items[ev["aggregate_id"]] = item
                    item["status"] = payload["to"]
                    item["version"] = int(item.get("version", 1)) + 1
                    item["updated_at"] = payload.get("updated_at", utc_now())
            elif et in ("inspection", "rectification"):
                rec = dict(payload["record"])
                rec["item_id"] = ev["aggregate_id"]
                records[rec["id"]] = rec
        return {"items": items, "records": records}

    def _materialize(self, state: Dict[str, Dict[int, Dict[str, Any]]]) -> None:
        self.conn.execute("DELETE FROM records")
        self.conn.execute("DELETE FROM items")
        for item_id in sorted(state["items"]):
            item = state["items"][item_id]
            self.conn.execute(
                """INSERT INTO items(id, title, description, severity, quantity, threshold,
                   status, version, external_ref, created_by, created_at, updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (item["id"], item.get("title", ""), item.get("description", ""),
                 item.get("severity", "low"), float(item.get("quantity", 0.0)),
                 float(item.get("threshold", 1.0)), item.get("status", "draft"),
                 int(item.get("version", 1)), item.get("external_ref"),
                 item.get("created_by", "ledger"), item.get("created_at", utc_now()),
                 item.get("updated_at", utc_now())))
        for rec_id in sorted(state["records"]):
            rec = state["records"][rec_id]
            self.conn.execute(
                """INSERT INTO records(id, item_id, kind, detail, status, external_ref,
                   created_by, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (rec["id"], rec["item_id"], rec.get("kind", "inspection"),
                 rec.get("detail", ""), rec.get("status", "open"),
                 rec.get("external_ref"), rec.get("created_by", "ledger"),
                 rec.get("created_at", utc_now())))
        # 同步 AUTOINCREMENT 序列，避免未来隐式插入撞号
        self.conn.execute(
            "INSERT OR REPLACE INTO sqlite_sequence(name, seq) VALUES('items', "
            "(SELECT COALESCE(MAX(id),0) FROM items))")
        self.conn.execute(
            "INSERT OR REPLACE INTO sqlite_sequence(name, seq) VALUES('records', "
            "(SELECT COALESCE(MAX(id),0) FROM records))")

    # ---------- 审计（幂等） ----------
    def _audit_action(self, ev: Dict[str, Any]) -> Optional[str]:
        if ev["event_type"] == "baseline":
            return None
        if ev["event_type"] == "permit":
            return "create" if ev["payload"].get("action") == "created" else "transition"
        return "record"

    def _append_audit_for_event(self, ev: Dict[str, Any]) -> None:
        action = self._audit_action(ev)
        if action is None:
            return
        detail = dict(ev["payload"].get("audit_detail") or {})
        detail.update({
            "event_type": ev["event_type"],
            "device_id": ev["device_id"],
            "device_seq": ev["device_seq"],
            "causal_seq": ev["causal_seq"],
            "aggregate_id": ev["aggregate_id"],
        })
        actor = ev["payload"].get("actor", ev["device_id"])
        row = self.conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        previous = row["entry_hash"] if row else GENESIS
        entry = make_entry(action, ENTITY, ev["aggregate_id"], actor, detail, previous)
        self.conn.execute(
            """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
               previous_hash, entry_hash, created_at, ledger_event_hash)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (entry["action"], entry["entity_type"], entry["entity_id"], entry["actor"],
             json.dumps(detail, ensure_ascii=False, sort_keys=True),
             entry["previous_hash"], entry["entry_hash"], entry["created_at"],
             ev["event_hash"]))

    # ---------- 基线（旧数据升级） ----------
    def ensure_baseline(self) -> List[Dict[str, Any]]:
        """把尚无事件对应的旧 items/records 升级为基线事件。幂等。"""
        with self._lock, self.conn:
            rows = self.conn.execute(
                """SELECT i.* FROM items i
                   WHERE NOT EXISTS (
                       SELECT 1 FROM ledger_events le
                       WHERE le.aggregate_type='item' AND le.aggregate_id=i.id
                   ) ORDER BY i.id""").fetchall()
            baselined: List[Dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                recs = [dict(r) for r in self.conn.execute(
                    "SELECT * FROM records WHERE item_id=? ORDER BY id", (item["id"],)
                ).fetchall()]
                baselined.append({
                    "device_id": f"baseline:{item['created_by']}:{item['id']}",
                    "device_seq": 1,
                    "event_type": "baseline",
                    "aggregate_type": "item",
                    "aggregate_id": item["id"],
                    "payload": {"item": item, "records": recs},
                })
            if baselined:
                # 基线事件直接追加（不写审计），随后折叠物化
                now = utc_now()
                last_hash = self._last_event_hash()
                for p in baselined:
                    ph = payload_hash(p["payload"])
                    causal = self._next_causal_seq()
                    eh = compute_event_hash(
                        last_hash, p["device_id"], p["device_seq"], causal,
                        p["event_type"], p["aggregate_type"], p["aggregate_id"], ph, now)
                    self.conn.execute(
                        """INSERT INTO ledger_events(device_id, device_seq, causal_seq, event_type,
                           aggregate_type, aggregate_id, payload, payload_hash, previous_hash,
                           event_hash, confirmed, created_at)
                           VALUES(?,?,?,?,?,?,?,?,?,?,1,?)""",
                        (p["device_id"], p["device_seq"], causal, p["event_type"],
                         p["aggregate_type"], p["aggregate_id"],
                         json.dumps(p["payload"], ensure_ascii=False, sort_keys=True),
                         ph, last_hash, eh, now))
                    p["causal_seq"] = causal
                    p["event_hash"] = eh
                    last_hash = eh
                state = self._fold(self._load_confirmed_events())
                self._materialize(state)
            return baselined

    # ---------- 快照与恢复 ----------
    def take_snapshot(self) -> Dict[str, Any]:
        with self._lock, self.conn:
            events = self._load_confirmed_events()
            state = self._fold(events)
            causal = self._last_causal_seq()
            state_json = json.dumps(
                {"items": state["items"], "records": state["records"]},
                ensure_ascii=False, sort_keys=True, default=str)
            shash = _sha256(state_json.encode("utf-8"))
            now = utc_now()
            cur = self.conn.execute(
                """INSERT INTO ledger_snapshots(causal_seq, state, state_hash, created_at)
                   VALUES(?,?,?,?)""",
                (causal, state_json, shash, now))
            return {"id": int(cur.lastrowid), "causal_seq": causal, "state_hash": shash}

    def _load_snapshot_state(self) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT * FROM ledger_snapshots ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            return None
        data = json.loads(row["state"])
        return {"items": {int(k): v for k, v in data["items"].items()},
                "records": {int(k): v for k, v in data["records"].items()}}

    def _verify_log(self) -> None:
        """校验因果连续性与事件哈希链；任何断裂或篡改都抛异常。"""
        rows = self.conn.execute(
            "SELECT * FROM ledger_events WHERE confirmed=1 ORDER BY causal_seq").fetchall()
        expected_causal = 1
        prev_hash = GENESIS
        for row in rows:
            if row["causal_seq"] != expected_causal:
                raise CausalGap(
                    f"因果缺号：期望 causal_seq={expected_causal} 实际 {row['causal_seq']}，停住并保留原结果")
            payload = json.loads(row["payload"])
            if payload_hash(payload) != row["payload_hash"]:
                raise ConfirmedEventTampered(
                    f"已确认事件被改写：{row['device_id']}#{row['device_seq']}，停住并保留原结果")
            if row["previous_hash"] != prev_hash:
                raise ConfirmedEventTampered(
                    f"已确认事件哈希链断裂：{row['device_id']}#{row['device_seq']}，停住并保留原结果")
            expect_eh = compute_event_hash(
                prev_hash, row["device_id"], row["device_seq"], row["causal_seq"],
                row["event_type"], row["aggregate_type"], row["aggregate_id"],
                row["payload_hash"], row["created_at"])
            if expect_eh != row["event_hash"]:
                raise ConfirmedEventTampered(
                    f"已确认事件哈希不匹配：{row['device_id']}#{row['device_seq']}，停住并保留原结果")
            prev_hash = row["event_hash"]
            expected_causal += 1

    def recover(self) -> Dict[str, Any]:
        """从最后确认事件恢复。

        校验事件账完整性：若有缺号或已确认事件被改写，停住并返回最后确认（快照）状态；
        校验通过则按因果序折叠重建。重放不重复（幂等）。
        """
        with self._lock, self.conn:
            try:
                self._verify_log()
            except (ConfirmedEventTampered, CausalGap) as exc:
                snap = self._load_snapshot_state()
                if snap is None:
                    snap = {"items": {}, "records": {}}
                return {"status": "halted", "reason": str(exc), "state": snap,
                        "last_causal_seq": self._last_causal_seq()}
            events = self._load_confirmed_events()
            state = self._fold(events)
            self._materialize(state)
            return {"status": "recovered", "state": state,
                    "last_causal_seq": self._last_causal_seq()}

    # ---------- 状态查询 ----------
    def ledger_status(self) -> Dict[str, Any]:
        with self._lock:
            total = self.conn.execute("SELECT COUNT(*) n FROM ledger_events").fetchone()["n"]
            confirmed = self.conn.execute(
                "SELECT COUNT(*) n FROM ledger_events WHERE confirmed=1").fetchone()["n"]
            devices = [r["device_id"] for r in self.conn.execute(
                "SELECT DISTINCT device_id FROM ledger_events ORDER BY device_id").fetchall()]
            return {"total": int(total), "confirmed": int(confirmed),
                    "last_causal_seq": self._last_causal_seq(), "devices": devices}
