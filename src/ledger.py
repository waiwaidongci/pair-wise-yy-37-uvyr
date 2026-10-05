"""设备序号 + 因果序号的事件账（纯逻辑部分）。

每个事件携带两个序号，二者职责不同：

* ``device_seq``：设备端单调序号，与 ``device_id`` 组成**设备序号键**。
  幂等去重、乱序识别、缺号检测都以它为准；设备断电重放同一个序号只会被接受一次。
* ``causal_prev``：**因果序号**，即前驱事件的设备序号键（基线/根为 ``None``）。
  当前状态不是按写入顺序、而是按因果关系重建；两台设备各自的设备序号互相独立，
  通过因果序号接成一条线性链。

事件一旦 ``confirmed``（确认）即不可改写：内容哈希不符按篡改处理，
非其后继的分支按“晚到覆盖”拒绝，二者都停在最后确认事件、保留原结果。
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .domain import (LedgerForkError, LedgerGapError, LedgerTamperError,
                     ValidationError)

# 三类变更 + 旧数据升级用的基线事件
LICENSE = "license"
INSPECTION = "inspection"
RECTIFICATION = "rectification"
BASELINE = "baseline"
EVENT_TYPES = (LICENSE, INSPECTION, RECTIFICATION, BASELINE)

ROOT_CAUSAL = None  # 因果链根（基线事件的前驱）
GENESIS_HASH = "GENESIS"

# 各事件类型的必填载荷字段（仅做形状校验，业务规则仍在 rules/service 层）
REQUIRED_FIELDS: Dict[str, Sequence[str]] = {
    LICENSE: ("license_no", "action"),
    INSPECTION: ("finding", "severity"),
    RECTIFICATION: ("action",),
    BASELINE: (),
}

# 因果链内允许的动作取值
LICENSE_ACTIONS = ("grant", "renew", "suspend", "revoke")
RECTIFICATION_ACTIONS = ("open", "close")


def event_key(device_id: str, device_seq: int) -> str:
    """设备序号键的规范文本形式，也是因果序号的引用形式。"""
    return f"{device_id}#{int(device_seq)}"


def parse_key(key: str) -> Tuple[str, str]:
    try:
        device_id, seq = key.rsplit("#", 1)
        if not device_id or not seq:
            raise ValueError
        return device_id, seq
    except (ValueError, AttributeError) as exc:
        raise ValidationError("因果序号格式错误，应为 device_id#seq") from exc


def canonical_payload(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def event_hash(previous_hash: str, event_type: str, item_id: int,
               device_id: str, device_seq: int, causal_prev: Optional[str],
               payload: Dict[str, Any]) -> str:
    """已确认事件的完整性哈希：内容 + 因果前驱共同入哈希。

    这样改动事件内容、或把它挂到另一个因果位置，都会使哈希对不上。
    """
    import hashlib
    body = json.dumps({
        "type": event_type,
        "item_id": item_id,
        "device_id": device_id,
        "device_seq": int(device_seq),
        "causal_prev": causal_prev,
        "payload": json.loads(canonical_payload(payload)),
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256()
    digest.update(previous_hash.encode("utf-8"))
    digest.update(b":")
    digest.update(body.encode("utf-8"))
    return digest.hexdigest()


def validate_event(event_type: str, device_id: str, device_seq: Any,
                   causal_prev: Any, payload: Any,
                   allow_baseline: bool = False) -> None:
    """校验单条补传/提交事件的形状。"""
    if not isinstance(device_id, str) or not device_id.strip():
        raise ValidationError("device_id不能为空")
    if isinstance(device_seq, bool) or not isinstance(device_seq, int) \
            or device_seq < 1:
        raise ValidationError("device_seq必须是正整数（设备端从1开始单调递增）")
    if causal_prev is not None:
        if not isinstance(causal_prev, str) or not causal_prev.strip():
            raise ValidationError("causal_prev必须是 device_id#seq 或 null")
        parse_key(causal_prev)
    allowed = EVENT_TYPES if allow_baseline else (LICENSE, INSPECTION, RECTIFICATION)
    if event_type not in allowed:
        raise ValidationError(f"事件类型必须是{', '.join(allowed)}之一")
    if not isinstance(payload, dict):
        raise ValidationError("payload必须是对象")
    for field in REQUIRED_FIELDS[event_type]:
        if field not in payload or payload[field] is None:
            raise ValidationError(f"{event_type}事件缺少字段: {field}")
    if event_type == RECTIFICATION and payload["action"] == "close" \
            and not str(payload.get("resolution", "")).strip():
        raise ValidationError("关闭整改必须填写resolution")
    if event_type == LICENSE and payload.get("action") not in LICENSE_ACTIONS:
        raise ValidationError(f"许可动作必须是{', '.join(LICENSE_ACTIONS)}之一")
    if event_type == RECTIFICATION and payload.get("action") not in RECTIFICATION_ACTIONS:
        raise ValidationError(f"整改动作必须是{', '.join(RECTIFICATION_ACTIONS)}之一")
    if event_type == INSPECTION and payload.get("severity") not in \
            ("low", "medium", "high", "critical"):
        raise ValidationError("检查发现severity不合法")


# ---------------------------------------------------------------------------
# 因果重建（拓扑化）与当前状态投影
# ---------------------------------------------------------------------------

def order_by_causality(events: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """按 causal_prev 将事件重排为因果顺序。

    线性链语义：每个事件最多一个后继；存在无法解析的前驱（缺号）、成环、
    或同一前驱出现两个后继（分叉）时抛错，调用方据此停在最后确认事件。
    """
    by_key: Dict[str, Dict[str, Any]] = {}
    for event in events:
        by_key[event["event_key"]] = event

    successors: Dict[Optional[str], List[str]] = {}
    for event in events:
        successors.setdefault(event["causal_prev"], []).append(event["event_key"])
    for prev, keys in successors.items():
        if len(set(keys)) > 1:
            raise LedgerForkError(f"因果序号 {prev} 后出现分叉，拒绝分叉重建")

    # 链头：causal_prev 不在本批事件集合中（指向批次外的已确认事件或根）
    roots = [e["event_key"] for e in events
             if e["causal_prev"] not in by_key]
    if not roots:
        raise LedgerGapError("因果链成环，找不到可重建的起点")

    ordered: List[Dict[str, Any]] = []
    visited: Set[str] = set()
    for root in roots:
        cursor: Optional[str] = root
        while cursor is not None:
            if cursor in visited:
                raise LedgerGapError("因果链成环")
            if cursor not in by_key:
                raise LedgerGapError(f"因果序号缺号: {cursor}")
            visited.add(cursor)
            ordered.append(by_key[cursor])
            nxt = successors.get(cursor, [])
            cursor = nxt[0] if nxt else None
    if len(ordered) != len(events):
        raise LedgerGapError("存在无法接入因果链的事件（缺号或孤儿事件）")
    return ordered


def initial_state() -> Dict[str, Any]:
    return {
        "license": None,           # 最近一次许可事件
        "inspection": None,        # 最近一次**已确认**检查结果（先确认者保留）
        "open_rectifications": {}, # rectification_id -> 事件载荷
        "head": None,              # 当前已确认链头的设备序号键
    }


def apply_event(state: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
    """把单个事件折叠进当前状态。"""
    event_type = event["type"]
    payload = dict(event["payload"])
    if event_type == BASELINE:
        state["license"] = payload.get("license")
        state["inspection"] = payload.get("inspection")
        for rectification in payload.get("open_rectifications", []):
            rid = str(rectification.get("rectification_id"))
            state["open_rectifications"][rid] = rectification
    elif event_type == LICENSE:
        state["license"] = payload
    elif event_type == INSPECTION:
        # 已确认链上的检查结果即为当前结果；因果链保证后来者只能从当前链头延伸，
        # 无法把先确认的结果“盖掉”。
        state["inspection"] = payload
    elif event_type == RECTIFICATION:
        rid = str(payload.get("rectification_id",
                              event["device_id"] + "-" + str(event["device_seq"])))
        if payload.get("action") == "close":
            state["open_rectifications"].pop(rid, None)
        else:
            state["open_rectifications"][rid] = payload
    state["head"] = event["event_key"]
    return state


def rebuild_state(events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """乱序补传按因果关系重建当前状态。"""
    state = initial_state()
    for event in order_by_causality(list(events)):
        apply_event(state, event)
    return state


# ---------------------------------------------------------------------------
# 补传规划：在写入前判定缺号 / 分叉 / 重放 / 成环
# ---------------------------------------------------------------------------

@dataclass
class StoredEvent:
    """存储层事件的最小视图。"""
    event_key: str
    causal_prev: Optional[str]
    type: str
    item_id: int
    device_id: str
    device_seq: int
    payload: Dict[str, Any]
    confirmed: bool
    entry_hash: str
    previous_hash: str
    created_at: str
    actor: str = "system"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "event_key": self.event_key, "causal_prev": self.causal_prev,
            "type": self.type, "item_id": self.item_id,
            "device_id": self.device_id, "device_seq": self.device_seq,
            "payload": self.payload, "confirmed": self.confirmed,
            "entry_hash": self.entry_hash, "previous_hash": self.previous_hash,
            "created_at": self.created_at, "actor": self.actor,
        }


def _ensure_device_continuity(device_id: str, batch_seqs: Set[int],
                              stored_seqs: Set[int]) -> None:
    """补传要求设备序号连续：1..max 每个序号要么已存储、要么在本批中。"""
    maximum = max(batch_seqs | stored_seqs)
    missing = [seq for seq in range(1, maximum + 1)
               if seq not in stored_seqs and seq not in batch_seqs]
    if missing:
        raise LedgerGapError(
            f"设备 {device_id} 序号缺号: {', '.join(map(str, sorted(missing)))}；"
            "已停在最后确认事件，原结果保留")


def plan_backfill(batch: Sequence[Dict[str, Any]],
                  stored: Sequence[Dict[str, Any]],
                  head_key: Optional[str]) -> List[Dict[str, Any]]:
    """规划一批补传事件。

    ``batch`` 元素为已通过 :func:`validate_event` 的事件字典
    （含 item_id/device_id/device_seq/causal_prev/type/payload）；
    ``stored`` 为该事项下全部事件（含未确认停放事件）。

    返回可直接按顺序插入的事件（因果顺序）。检测到重放、缺号、分叉、成环时抛错。
    """
    stored_map = {e["event_key"]: e for e in stored}

    fresh: List[Dict[str, Any]] = []
    replay: List[Dict[str, Any]] = []
    batch_keys: Set[str] = set()
    per_device_new: Dict[str, Set[int]] = {}
    for event in batch:
        key = event_key(event["device_id"], event["device_seq"])
        event["event_key"] = key
        if key in batch_keys:
            raise ValidationError(f"补传批次内设备序号重复: {key}")
        batch_keys.add(key)
        per_device_new.setdefault(event["device_id"], set()).add(event["device_seq"])
        if key in stored_map:
            old = stored_map[key]
            # 断电重放：同键且内容一致 → 幂等跳过（不重复写、不重复审计）
            if (old["type"] == event["type"]
                    and canonical_payload(old["payload"]) == canonical_payload(event["payload"])
                    and old["causal_prev"] == event["causal_prev"]):
                replay.append(event)
                continue
            # 键相同但内容/因果位置不同 = 改动已用序号（若已确认即篡改）
            if old.get("confirmed"):
                raise LedgerTamperError(
                    f"已确认事件 {key} 被改动，拒绝写入并保留原结果")
            raise LedgerForkError(f"未确认事件 {key} 的内容与已停放版本冲突")
        fresh.append(event)

    if not fresh:
        return []  # 整批都是重放

    # 设备序号连续性（缺号检测），按设备分别判断
    per_device_stored: Dict[str, Set[int]] = {}
    for event in stored:
        per_device_stored.setdefault(event["device_id"], set()).add(event["device_seq"])
    for device_id, seqs in per_device_new.items():
        _ensure_device_continuity(device_id, seqs,
                                  per_device_stored.get(device_id, set()))

    # 分叉检测：从每个新事件沿因果前驱回溯，必须能落到当前已确认链头或根。
    def resolve(key: Optional[str], trail: Set[str]) -> Optional[str]:
        if key is None:
            return None
        if key in trail:
            raise LedgerGapError(f"因果链在 {key} 处成环")
        if key in stored_map:
            return key
        if key in batch_keys:
            for event in fresh:
                if event["event_key"] == key:
                    return resolve(event["causal_prev"], trail | {key})
        raise LedgerGapError(f"因果序号无法解析（缺号）: {key}；"
                             "已停在最后确认事件，原结果保留")

    base_keys: Set[Optional[str]] = set()
    for event in fresh:
        base = resolve(event["causal_prev"], {event["event_key"]})
        base_keys.add(base)
    if head_key is not None and any(b != head_key for b in base_keys):
        # 新批次想从旧链头之外的位置接出来 —— 晚到版本会盖掉已确认结果
        raise LedgerForkError(
            "补传事件不是当前已确认链头的后继，拒绝覆盖已确认结果")

    ordered = order_by_causality(fresh)
    return ordered


def plan_pending(batch: Sequence[Dict[str, Any]],
                 stored: Sequence[Dict[str, Any]],
                 head_key: Optional[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """断网现场模式的宽松规划（需调用方显式 opt-in）。

    与 :func:`plan_backfill` 的区别：因果前驱尚未到达的事件允许**停放**，
    不视为缺号；但篡改设备序号、指向非链头的已确认事件（分叉）仍然拒绝。

    返回 ``(可立即确认的因果有序事件, 待前驱到达的停放事件)``。
    """
    stored_map = {e["event_key"]: e for e in stored}
    fresh: List[Dict[str, Any]] = []
    batch_keys: Set[str] = set()
    for event in batch:
        key = event_key(event["device_id"], event["device_seq"])
        event["event_key"] = key
        if key in batch_keys:
            raise ValidationError(f"补传批次内设备序号重复: {key}")
        batch_keys.add(key)
        if key in stored_map:
            old = stored_map[key]
            if (old["type"] == event["type"]
                    and canonical_payload(old["payload"]) == canonical_payload(event["payload"])
                    and old["causal_prev"] == event["causal_prev"]):
                continue  # 重放
            if old.get("confirmed"):
                raise LedgerTamperError(f"已确认事件 {key} 被改动，拒绝并保留原结果")
            raise LedgerForkError(f"未确认事件 {key} 与停放版本冲突")
        fresh.append(event)

    confirmed_keys = {e["event_key"] for e in stored if e.get("confirmed")}
    # 从真实链头出发，把“本批事件 + 已停放事件”当作候选集做拓扑遍历。
    # 已停放事件只充当“桥”：只有本批补上了它缺失的前驱，这一串才会到达。
    candidates: Dict[str, Dict[str, Any]] = {
        e["event_key"]: e for e in fresh}
    candidates.update({e["event_key"]: e for e in stored if not e.get("confirmed")})
    by_prev: Dict[Optional[str], List[Dict[str, Any]]] = {}
    for event in candidates.values():
        by_prev.setdefault(event["causal_prev"], []).append(event)

    fresh_keys = {e["event_key"] for e in fresh}
    reachable: Set[str] = set()
    frontier = [head_key]
    while frontier:
        key = frontier.pop()
        for event in by_prev.get(key, []):
            if event["event_key"] not in reachable and \
                    event["event_key"] not in confirmed_keys:
                # 只把本批事件计入“可确认”；停放事件仅推进遍历
                if event["event_key"] in fresh_keys:
                    reachable.add(event["event_key"])
                frontier.append(event["event_key"])

    # 指向任何非链头已确认事件 = 想从历史中间分叉，拒绝
    for event in fresh:
        prev = event["causal_prev"]
        if prev in confirmed_keys and prev != head_key:
            raise LedgerForkError(
                f"事件 {event['event_key']} 想接在已确认事件 {prev} 之后，"
                "但它不是当前链头：拒绝覆盖已确认结果")

    confirmable = order_by_causality(
        [e for e in fresh if e["event_key"] in reachable]) \
        if reachable else []
    parkable = [e for e in fresh if e["event_key"] not in reachable]
    return confirmable, parkable


# ---------------------------------------------------------------------------
# 已确认事件的完整性校验
# ---------------------------------------------------------------------------

def verify_confirmed_chain(confirmed_events: Sequence[Dict[str, Any]]) -> None:
    """逐条重算哈希。任何已确认事件被改动都在此处暴露。"""
    previous_hash = GENESIS_HASH
    seen: Set[Optional[str]] = set()
    head: Optional[str] = None
    for index, event in enumerate(confirmed_events):  # 调用方按因果顺序传入
        expected_prev = None if index == 0 else head
        if event["causal_prev"] != expected_prev:
            raise LedgerGapError(
                f"确认链在 {event['event_key']} 处与因果序号 "
                f"{event['causal_prev']} 不连续")
        if event["event_key"] in seen:
            raise LedgerForkError(f"确认链出现重复事件 {event['event_key']}")
        seen.add(event["event_key"])
        expected = event_hash(
            previous_hash, event["type"], event["item_id"],
            event["device_id"], event["device_seq"], event["causal_prev"],
            event["payload"])
        if expected != event["entry_hash"]:
            raise LedgerTamperError(
                f"已确认事件 {event['event_key']} 哈希不符，疑似被篡改；"
                "停在最后确认事件，原结果保留")
        previous_hash = event["entry_hash"]
        head = event["event_key"]
