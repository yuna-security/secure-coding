"""채팅 서비스 (P5, R3) — 검증·저장·DM 방 권한.

- ⑬⑮ 메시지 길이·내용 서버측 검증  - V-05/AC3.3 발신자는 서버 세션으로만 결정
- AC3.2/§5·§7 DM은 방 참여자(a 또는 b)만 읽기/쓰기 — 서버측 재검증(IDOR 방지)
- 라우트/이벤트 계층은 얇게, 규칙·트랜잭션은 여기로 모아 테스트 가능하게 한다.
"""
from flask import current_app
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import NotFound, Forbidden

from ..extensions import db
from ..models import User, DMRoom, ChatMessage
from ..auth.service import ValidationError


def validate_content(content: str) -> str:
    if not isinstance(content, str):
        raise ValidationError("메시지 형식이 올바르지 않습니다.")
    content = content.strip()
    if not content:
        raise ValidationError("메시지를 입력하세요.")
    limit = current_app.config["CHAT_MESSAGE_MAX"]
    if len(content) > limit:
        raise ValidationError(f"메시지는 최대 {limit}자까지 입력할 수 있습니다.")
    return content


# ---------- 전체 채팅 (AC3.1) ----------

def _active_sender(sender: User) -> User:
    """서비스 직접 호출에서도 현재 DB의 활성 사용자인지 재검증한다."""
    sender_id = getattr(sender, "id", None)
    current = (
        db.session.get(User, sender_id, populate_existing=True)
        if sender_id
        else None
    )
    if current is None or not current.is_active:
        raise Forbidden()
    return current


def post_global_message(sender: User, content: str) -> ChatMessage:
    sender = _active_sender(sender)
    content = validate_content(content)
    message = ChatMessage(
        scope="global",
        sender_id=sender.id,  # 클라이언트가 보낸 신원 무시 — 세션 사용자로만 결정
        content=content,
    )
    try:
        db.session.add(message)
        db.session.commit()
        return message
    except Exception:
        db.session.rollback()
        raise


def recent_global(limit: int = None):
    limit = limit or current_app.config["CHAT_HISTORY_LIMIT"]
    rows = (
        ChatMessage.query.filter(ChatMessage.scope == "global")
        .order_by(ChatMessage.created_at.desc())
        .limit(limit)
        .all()
    )
    return list(reversed(rows))  # 오래된→최신 순으로 표시


# ---------- 1:1 DM (AC3.2) ----------

def get_active_user_or_404(user_id: str) -> User:
    user = (
        db.session.get(User, user_id, populate_existing=True)
        if isinstance(user_id, str)
        else None
    )
    if user is None or user.status != "active":
        raise NotFound()
    return user


def _normalized_pair(id1: str, id2: str):
    """dm_room은 CHECK(user_a_id < user_b_id)로 정규화 — 방향 중복 방지."""
    return (id1, id2) if id1 < id2 else (id2, id1)


def get_or_create_dm_room(me: User, other_id: str) -> DMRoom:
    me = _active_sender(me)
    other = get_active_user_or_404(other_id)
    if other.id == me.id:
        raise ValidationError("자기 자신과는 DM할 수 없습니다.")
    a_id, b_id = _normalized_pair(me.id, other.id)
    room = DMRoom.query.filter_by(user_a_id=a_id, user_b_id=b_id).first()
    if room is not None:
        return room
    room = DMRoom(user_a_id=a_id, user_b_id=b_id)
    try:
        db.session.add(room)
        db.session.commit()
        return room
    except IntegrityError:
        # 동시에 같은 방이 생성된 경쟁조건 — 기존 방을 재조회한다.
        db.session.rollback()
        existing = DMRoom.query.filter_by(user_a_id=a_id, user_b_id=b_id).first()
        if existing is None:
            raise
        return existing


def get_room_or_404(room_id: str) -> DMRoom:
    room = db.session.get(DMRoom, room_id)
    if room is None:
        raise NotFound()
    return room


def is_participant(room: DMRoom, user_id: str) -> bool:
    return user_id in (room.user_a_id, room.user_b_id)


def ensure_participant(room: DMRoom, user_id: str) -> None:
    """방 참여자만 읽기/쓰기 허용(§7). 비참여자는 403."""
    if not is_participant(room, user_id):
        raise Forbidden()


def room_if_participant(room_id: str, user_id: str):
    """참여자인 방만 반환(join_dm용). 미존재/비참여는 None으로 조용히 거부."""
    if not isinstance(room_id, str) or not room_id:
        return None
    room = db.session.get(DMRoom, room_id)
    if (
        room is None
        or not is_participant(room, user_id)
        or not _room_participants_active(room)
    ):
        return None
    return room


def _room_participants_active(room: DMRoom) -> bool:
    """현재 두 참여자가 모두 active인지 확인한다."""
    active_count = User.query.filter(
        User.id.in_((room.user_a_id, room.user_b_id)),
        User.status == "active",
    ).count()
    return active_count == 2


def post_dm_message(sender: User, room_id: str, content: str) -> ChatMessage:
    sender = _active_sender(sender)
    if not isinstance(room_id, str):
        raise NotFound()
    room = get_room_or_404(room_id)
    ensure_participant(room, sender.id)  # 서버측 재검증(클라 room_id 신뢰 금지)
    if not _room_participants_active(room):
        raise Forbidden()
    content = validate_content(content)
    message = ChatMessage(
        scope="dm",
        dm_room_id=room.id,
        sender_id=sender.id,
        content=content,
    )
    try:
        db.session.add(message)
        db.session.commit()
        return message
    except Exception:
        db.session.rollback()
        raise


def dm_history(room: DMRoom, limit: int = None):
    limit = limit or current_app.config["CHAT_HISTORY_LIMIT"]
    rows = (
        ChatMessage.query.filter(
            ChatMessage.scope == "dm", ChatMessage.dm_room_id == room.id
        )
        .order_by(ChatMessage.created_at.desc())
        .limit(limit)
        .all()
    )
    return list(reversed(rows))
