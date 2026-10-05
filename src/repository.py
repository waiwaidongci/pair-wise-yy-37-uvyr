from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import (ConflictError, LedgerForkError, LedgerTamperError,
                     NotFoundError)
from .ledger import (GENESIS_HASH, canonical_payload, event_hash, event_key,
                     initial_state, apply_event, rebuild_state,
                     verify_confirmed_chain)
from .rules import ID_PREFIX, STATES


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        with self.conn:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    dedup_key TEXT UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ledger_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    device_id TEXT NOT NULL,
                    device_seq INTEGER NOT NULL,
                    event_key TEXT NOT NULL,
                    causal_prev TEXT,
                    type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    confirmed INTEGER NOT NULL DEFAULT 1,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT 'device',
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, event_key)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_ledger_causal
                    ON ledger_events(item_id, causal_prev)
                    WHERE confirmed = 1 AND causal_prev IS NOT NULL;
                CREATE UNIQUE INDEX IF NOT EXISTS ux_ledger_root
                    ON ledger_events(item_id)
                    WHERE confirmed = 1 AND causal_prev IS NULL;
                CREATE INDEX IF NOT EXISTS ix_ledger_pending
                    ON ledger_events(item_id, confirmed);
                CREATE TABLE IF NOT EXISTS ledger_checkpoints (
                    item_id INTEGER PRIMARY KEY REFERENCES items(id) ON DELETE CASCADE,
                    head_key TEXT,
                    head_hash TEXT NOT NULL DEFAULT 'GENESIS',
                    state TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)
        self._upgrade_audit_schema()

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def _upgrade_audit_schema(self) -> None:
        """旧库补列：审计去重键（断电重放时同键不重复写）。"""
        with self._lock, self.conn:
            cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(audit_events)")}
            if "dedup_key" not in cols:
                self.conn.execute(
                    "ALTER TABLE audit_events ADD COLUMN dedup_key TEXT")
                self.conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_dedup"
                    " ON audit_events(dedup_key) WHERE dedup_key IS NOT NULL")

    # ------------------------------------------------------------------
    # 事件账
    # ------------------------------------------------------------------
    @staticmethod
    def _event_row(row: sqlite3.Row) -> Dict[str, Any]:
        event = dict(row)
        event["payload"] = json.loads(event["payload"])
        event["confirmed"] = bool(event["confirmed"])
        return event

    def _load_checkpoint(self, item_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM ledger_checkpoints WHERE item_id=?",
                (item_id,)).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["state"] = json.loads(result["state"])
        return result

    def get_checkpoint(self, item_id: int) -> Dict[str, Any]:
        cp = self._load_checkpoint(item_id)
        if cp is None:
            return {"head_key": None, "head_hash": GENESIS_HASH,
                    "state": initial_state()}
        return cp

    def list_ledger_events(self, item_id: int,
                           confirmed: Optional[bool] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM ledger_events WHERE item_id=?"
        params: tuple = (item_id,)
        if confirmed is not None:
            sql += " AND confirmed=?"
            params = (item_id, 1 if confirmed else 0)
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._event_row(r) for r in rows]

    def _get_event(self, conn, item_id: int, key: str) -> Optional[Dict[str, Any]]:
        row = conn.execute(
            "SELECT * FROM ledger_events WHERE item_id=? AND event_key=?",
            (item_id, key)).fetchone()
        return self._event_row(row) if row else None

    def _drain_pending(self, conn, item_id: int,
                       state: Dict[str, Any], head_key: Optional[str],
                       head_hash: str) -> Tuple[Dict[str, Any], Optional[str], str, int]:
        """停放事件一旦前驱到达即自动确认，沿因果链顺序折叠进状态。"""
        confirmed_count = 0
        while True:
            row = conn.execute(
                """SELECT * FROM ledger_events
                   WHERE item_id=? AND confirmed=0 AND causal_prev IS ?
                   ORDER BY id LIMIT 1""",
                (item_id, head_key)).fetchone()
            if row is None:
                break
            event = self._event_row(row)
            digest = event_hash(head_hash, event["type"], event["item_id"],
                                event["device_id"], event["device_seq"],
                                event["causal_prev"], event["payload"])
            conn.execute(
                "UPDATE ledger_events SET confirmed=1, previous_hash=?, entry_hash=? "
                "WHERE id=?", (head_hash, digest, event["id"]))
            event["previous_hash"] = head_hash
            event["entry_hash"] = digest
            apply_event(state, event)
            head_key = event["event_key"]
            head_hash = digest
            confirmed_count += 1
        return state, head_key, head_hash, confirmed_count

    def _save_checkpoint(self, conn, item_id: int, state: Dict[str, Any],
                         head_key: Optional[str], head_hash: str) -> None:
        conn.execute(
            """INSERT INTO ledger_checkpoints(item_id, head_key, head_hash, state, updated_at)
               VALUES(?,?,?,?,?)
               ON CONFLICT(item_id) DO UPDATE SET
                 head_key=excluded.head_key, head_hash=excluded.head_hash,
                 state=excluded.state, updated_at=excluded.updated_at""",
            (item_id, head_key, head_hash,
             json.dumps(state, ensure_ascii=False, sort_keys=True,
                        default=str), utc_now()))

    def _append_audit_in(self, conn, action: str, entity_type: str, entity_id: int,
                         actor: str, detail: dict, dedup_key: Optional[str]) -> None:
        """在调用方事务内追加审计；dedup_key 冲突即说明是重放，跳过不重复写。"""
        if dedup_key is not None:
            exists = conn.execute(
                "SELECT 1 FROM audit_events WHERE dedup_key=?",
                (dedup_key,)).fetchone()
            if exists:
                return
        row = conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        previous = row["entry_hash"] if row else "GENESIS"
        event = make_entry(action, entity_type, entity_id, actor, detail, previous)
        conn.execute(
            """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
               previous_hash, entry_hash, dedup_key, created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (event["action"], event["entity_type"], event["entity_id"], event["actor"],
             json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
             event["previous_hash"], event["entry_hash"], dedup_key,
             event["created_at"]))

    def park_pending_event(self, item_id: int, event_type: str, device_id: str,
                           device_seq: int, causal_prev: Optional[str],
                           payload: dict, actor: str) -> Dict[str, Any]:
        """显式停放一条乱序事件：前驱尚未到达，不改变当前确认状态。

        前驱经补传到达后由 drain 自动确认；补传失败可用 recover 丢弃。
        """
        self.get_item(item_id)
        key = event_key(device_id, device_seq)
        with self._lock, self.conn:
            existing = self._get_event(self.conn, item_id, key)
            if existing is not None:
                if (existing["type"] == event_type
                        and canonical_payload(existing["payload"]) == canonical_payload(payload)
                        and existing["causal_prev"] == causal_prev):
                    return existing
                raise LedgerForkError(f"事件 {key} 已有不同版本")
            cur = self.conn.execute(
                """INSERT INTO ledger_events(item_id, device_id, device_seq, event_key,
                   causal_prev, type, payload, confirmed, previous_hash, entry_hash,
                   actor, created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (item_id, device_id, device_seq, key, causal_prev, event_type,
                 canonical_payload(payload), 0, "", "", actor, utc_now()))
            self._append_audit_in(
                self.conn, f"ledger.{event_type}.park", "排污许可", item_id, actor,
                {"event_key": key, "causal_prev": causal_prev,
                 "device_seq": device_seq, "confirmed": False},
                f"ledger:{item_id}:{key}")
            result = self._get_event(self.conn, item_id, key)
        return result or {}

    def append_ledger_event(self, item_id: int, event_type: str, device_id: str,
                            device_seq: int, causal_prev: Optional[str],
                            payload: dict, actor: str) -> Dict[str, Any]:
        """在线提交：链头后继立即确认，否则乱序事件先停放（不改变当前状态）。"""
        self.get_item(item_id)
        key = event_key(device_id, device_seq)
        dedup = f"ledger:{item_id}:{key}"
        with self._lock, self.conn:
            existing = self._get_event(self.conn, item_id, key)
            if existing is not None:
                if (existing["type"] == event_type
                        and canonical_payload(existing["payload"]) == canonical_payload(payload)
                        and existing["causal_prev"] == causal_prev):
                    return existing  # 完整重放：不重复写事件/审计
                if existing["confirmed"]:
                    raise LedgerTamperError(
                        f"已确认事件 {key} 被改动，拒绝写入并保留原结果")
                raise LedgerForkError(f"事件 {key} 已有不同的停放版本")

            cp = self._load_checkpoint(item_id)
            if cp is None:
                state, head_key, head_hash = initial_state(), None, GENESIS_HASH
            else:
                state, head_key, head_hash = cp["state"], cp["head_key"], cp["head_hash"]

            now = utc_now()
            if causal_prev != head_key:
                # 在线提交必须接当前已确认链头；接不上说明是晚到的分叉，
                # 不能停放后再悄悄确认，更不能覆盖已确认结果
                raise LedgerForkError(
                    f"因果序号 {causal_prev} 不是当前链头 {head_key}："
                    "晚到的提交不能覆盖已确认结果")
            previous_hash, digest = head_hash, event_hash(
                head_hash, event_type, item_id, device_id, device_seq,
                causal_prev, payload)

            try:
                cur = self.conn.execute(
                    """INSERT INTO ledger_events(item_id, device_id, device_seq, event_key,
                       causal_prev, type, payload, confirmed, previous_hash, entry_hash,
                       actor, created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (item_id, device_id, device_seq, key, causal_prev, event_type,
                     canonical_payload(payload), 1,
                     previous_hash, digest, actor, now))
            except sqlite3.IntegrityError as exc:
                # 唯一因果索引：同一因果序号只能有一个已确认后继
                raise LedgerForkError(
                    "该因果序号已有后继：晚到的提交不能覆盖已确认结果") from exc
            event_id = int(cur.lastrowid)

            stored = self._event_row(self.conn.execute(
                "SELECT * FROM ledger_events WHERE id=?", (event_id,)).fetchone())
            apply_event(state, stored)
            head_key, head_hash = key, digest
            # 在线确认后，顺带把此前乱序停放的后继贯通
            state, head_key, head_hash, parked = self._drain_pending(
                self.conn, item_id, state, head_key, head_hash)
            self._save_checkpoint(self.conn, item_id, state, head_key, head_hash)
            self._append_audit_in(
                self.conn, f"ledger.{event_type}.confirm",
                "排污许可", item_id, actor,
                {"event_key": key, "causal_prev": causal_prev,
                 "device_seq": device_seq, "confirmed": True,
                 "drained": parked, **{k: v for k, v in payload.items()
                                       if isinstance(v, (str, int, float, bool))}},
                dedup)
            result = self._get_event(self.conn, item_id, key)
        return result or {}

    def backfill_ledger_events(self, item_id: int,
                               ordered_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """补传：规划好的事件按因果顺序在单事务内插入并确认。

        全部事件的 causal_prev 已由 ledger.plan_backfill 验证为链头后继，
        因此整批直接确认；任何一步失败整批回滚，原结果保留。
        """
        self.get_item(item_id)
        with self._lock, self.conn:
            cp = self._load_checkpoint(item_id)
            if cp is None:
                state, head_key, head_hash = initial_state(), None, GENESIS_HASH
            else:
                state, head_key, head_hash = cp["state"], cp["head_key"], cp["head_hash"]
            now = utc_now()
            inserted = 0
            for event in ordered_events:
                key = event["event_key"]
                digest = event_hash(head_hash, event["type"], item_id,
                                    event["device_id"], event["device_seq"],
                                    event["causal_prev"], event["payload"])
                try:
                    self.conn.execute(
                        """INSERT INTO ledger_events(item_id, device_id, device_seq, event_key,
                           causal_prev, type, payload, confirmed, previous_hash, entry_hash,
                           actor, created_at)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (item_id, event["device_id"], event["device_seq"], key,
                         event["causal_prev"], event["type"],
                         canonical_payload(event["payload"]), 1, head_hash, digest,
                         event.get("actor", "device"), now))
                except sqlite3.IntegrityError as exc:
                    raise LedgerForkError(
                        "补传事件与已确认因果链冲突，拒绝覆盖") from exc
                stored = {"event_key": key, "causal_prev": event["causal_prev"],
                          "type": event["type"], "item_id": item_id,
                          "device_id": event["device_id"],
                          "device_seq": event["device_seq"],
                          "payload": event["payload"]}
                apply_event(state, stored)
                head_key, head_hash = key, digest
                inserted += 1
                self._append_audit_in(
                    self.conn, f"ledger.{event['type']}.backfill",
                    "排污许可", item_id, event.get("actor", "device"),
                    {"event_key": key, "causal_prev": event["causal_prev"],
                     "device_seq": event["device_seq"], "backfill": True},
                    f"ledger:{item_id}:{key}")
            if inserted:
                # 补传后若有此前停放的孤儿事件也能接上
                state, head_key, head_hash, parked = self._drain_pending(
                    self.conn, item_id, state, head_key, head_hash)
                self._save_checkpoint(self.conn, item_id, state, head_key, head_hash)
        return {"inserted": inserted,
                "checkpoint": self.get_checkpoint(item_id)}

    def recover_ledger(self, item_id: int) -> Dict[str, Any]:
        """补传失败后恢复：丢弃未确认的停放事件，从最后确认事件重建。

        重放只认设备序号键，重复提交不会再产生审计。
        """
        self.get_item(item_id)
        with self._lock, self.conn:
            confirmed_rows = self.conn.execute(
                "SELECT * FROM ledger_events WHERE item_id=? AND confirmed=1 "
                "ORDER BY id", (item_id,)).fetchall()
            confirmed = [self._event_row(r) for r in confirmed_rows]
            # 确认事件必须自身完整：哈希链断了（改过已确认事件）就停住
            from .ledger import order_by_causality
            verify_confirmed_chain(order_by_causality(confirmed))
            state = rebuild_state(confirmed)
            head = state["head"]
            head_hash = confirmed_rows[-1]["entry_hash"] if confirmed_rows else GENESIS_HASH
            discarded = self.conn.execute(
                "DELETE FROM ledger_events WHERE item_id=? AND confirmed=0",
                (item_id,)).rowcount
            self._save_checkpoint(self.conn, item_id, state, head, head_hash)
        return {"head_key": head, "discarded_pending": discarded,
                "state": state, "replayed": False}

    def ledger_state(self, item_id: int) -> Dict[str, Any]:
        self.get_item(item_id)
        cp = self._load_checkpoint(item_id)
        if cp is not None:
            state = cp["state"]
        else:
            state = rebuild_state([
                self._event_row(r) for r in self.conn.execute(
                    "SELECT * FROM ledger_events WHERE item_id=? AND confirmed=1",
                    (item_id,)).fetchall()])
        pending = self.conn.execute(
            "SELECT COUNT(*) AS n FROM ledger_events "
            "WHERE item_id=? AND confirmed=0", (item_id,)).fetchone()
        return {"state": state, "pending": int(pending["n"]),
                "confirmed_head": cp["head_key"] if cp else state["head"]}

    def verify_ledger(self, item_id: int) -> bool:
        self.get_item(item_id)
        from .ledger import order_by_causality
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM ledger_events WHERE item_id=? AND confirmed=1",
                (item_id,)).fetchall()
        verify_confirmed_chain(order_by_causality(
            [self._event_row(r) for r in rows]))
        return True

    def upgrade_legacy_baseline(self) -> List[int]:
        """旧数据升级：每个尚无事件账的事项，把表内当前结果固化成基线事件。

        基线事件为因果链根（causal_prev=NULL，设备固定为 legacy，序号 0 之外
        用 event_key 'legacy#baseline-<item>'），审计只追加一次。
        """
        upgraded: List[int] = []
        with self._lock:
            item_rows = self.conn.execute("SELECT id FROM items ORDER BY id").fetchall()
            for row in item_rows:
                item_id = int(row["id"])
                exists = self.conn.execute(
                    "SELECT 1 FROM ledger_events WHERE item_id=? LIMIT 1",
                    (item_id,)).fetchone()
                if exists:
                    continue
                with self.conn:
                    records = [dict(r) for r in
                               self.conn.execute(
                                   "SELECT kind, detail, status, external_ref, created_by "
                                   "FROM records WHERE item_id=? ORDER BY id",
                                   (item_id,)).fetchall()]
                    item = self._item(self.conn.execute(
                        "SELECT * FROM items WHERE id=?", (item_id,)).fetchone())
                    payload = {
                        "upgraded_from": "records",
                        "item_status": item["status"],
                        "license": {"license_no": item.get("external_ref"),
                                    "action": "grant"} if item.get("external_ref") else None,
                        "inspection": None,
                        "open_rectifications": [
                            {"rectification_id": str(r["external_ref"] or idx),
                             "action": "open", "detail": r["detail"]}
                            for idx, r in enumerate(records, start=1)
                            if r["status"] == "open"],
                    }
                    key = f"legacy#baseline-{item_id}"
                    digest = event_hash(GENESIS_HASH, "baseline", item_id,
                                        "legacy", 0, None, payload)
                    now = utc_now()
                    self.conn.execute(
                        """INSERT INTO ledger_events(item_id, device_id, device_seq, event_key,
                           causal_prev, type, payload, confirmed, previous_hash, entry_hash,
                           actor, created_at)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (item_id, "legacy", 0, key, None, "baseline",
                         canonical_payload(payload), 1, GENESIS_HASH, digest,
                         "migration", now))
                    state = initial_state()
                    apply_event(state, {"event_key": key, "causal_prev": None,
                                        "type": "baseline", "item_id": item_id,
                                        "device_id": "legacy", "device_seq": 0,
                                        "payload": payload})
                    self._save_checkpoint(self.conn, item_id, state, key, digest)
                    self._append_audit_in(
                        self.conn, "ledger.baseline.upgrade", "排污许可", item_id,
                        "migration", {"event_key": key, "records": len(records)},
                        f"ledger:{item_id}:{key}")
                    upgraded.append(item_id)
        return upgraded

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict,
                     dedup_key: Optional[str] = None) -> Dict[str, Any]:
        with self._lock, self.conn:
            self._append_audit_in(self.conn, action, entity_type, entity_id,
                                  actor, detail, dedup_key)
            row = self.conn.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        event = dict(row)
        event["detail"] = json.loads(event["detail"])
        return event

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now),
                )
                item_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    def close(self) -> None:
        with self._lock:
            self.conn.close()
