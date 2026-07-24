"""Socket.IO 이벤트 핸들러 (P5, R3).

보안 핵심(설계 §3·§4, 체크리스트 ⑬⑭⑮⑯):
- ⑭ connect 시 세션 인증 확인 — 미인증 연결은 거부(return False). Origin 제한은
  팩토리의 socketio.init_app(cors_allowed_origins) 동일 출처 정책으로 강제.
- V-05/AC3.3 발신자는 항상 서버 세션 사용자 ID로 결정 — 클라이언트가 보낸
  username/sender_id는 신뢰하지 않는다.
- AC3.2/§7 DM 이벤트는 방 참여자만 — 서버측 재검증(클라 room_id 신뢰 금지).
- ⑯ 사용자 ID 기반 이벤트 Rate Limit(Flask-Limiter와 별개, ratelimit.py).
- XSS: 소켓으로는 원문을 전달하고 클라이언트가 textContent로 무해 렌더링한다.
  진입 시 HTTP로 그리는 히스토리는 Jinja 자동 이스케이프가 담당한다.
"""
from flask import request, session
from flask_socketio import emit, join_room, disconnect
from werkzeug.exceptions import Forbidden, NotFound

from ..extensions import db
from ..models import User
from ..auth.service import ValidationError
from . import service as chat_service
from .connections import remember_connection, forget_connection
from .ratelimit import chat_rate_ok


def _actor():
    """소켓 연결의 세션에서 직접 신원을 확정한다.

    current_user(LocalProxy)는 앱 컨텍스트의 g에 캐시되어, 소켓 핸들러가 다른
    컨텍스트의 캐시를 재사용할 여지가 있다. 요청 스코프 세션의 사용자 id로 매 이벤트
    DB에서 사용자를 다시 로드해 신원 혼선과 stale 상태(휴면 등)를 원천 차단한다.
    """
    uid = session.get("_user_id")  # Flask-Login이 저장하는 사용자 id 키
    if not uid:
        return None
    # identity map에 남은 객체가 아니라 현재 DB 상태를 강제로 다시 읽는다.
    user = db.session.get(User, uid, populate_existing=True)
    if user is None or not user.is_active:  # 휴면 계정은 즉시 무효
        return None
    return user


def _serialize(message, sender):
    # 원문 그대로 전달 — 클라이언트가 textContent로 안전 렌더링(서버는 길이·형식 검증).
    return {
        "id": message.id,
        "scope": message.scope,
        "room_id": message.dm_room_id,
        "sender_id": message.sender_id,
        "username": sender.username if sender else "?",
        "content": message.content,
        # DB의 naive datetime은 UTC로 통일되어 있으므로 브라우저에 UTC임을 명시한다.
        "created_at": message.created_at.isoformat(timespec="seconds") + "Z",
    }


def _field(data, key):
    """Socket payload가 객체가 아니어도 예외 없이 빈 값으로 거부한다."""
    return data.get(key, "") if isinstance(data, dict) else ""


def register_chat_events(socketio):
    @socketio.on("connect")
    def handle_connect(auth=None):
        # ⑭ 미인증 연결 차단.
        user = _actor()
        if user is None:
            return False
        remember_connection(user.id, request.sid)
        return True

    @socketio.on("disconnect")
    def handle_disconnect(reason=None):
        forget_connection(request.sid)

    @socketio.on("global_message")
    def handle_global_message(data):
        user = _actor()
        if user is None:
            disconnect()
            return
        if not chat_rate_ok(user.id):
            emit("chat_error", {"error": "메시지를 너무 빠르게 보냈습니다."})
            return
        content = _field(data, "content")
        try:
            message = chat_service.post_global_message(user, content)
        except ValidationError as exc:
            emit("chat_error", {"error": str(exc)})
            return
        except Forbidden:
            disconnect()
            return
        emit("global_message", _serialize(message, user), broadcast=True)

    @socketio.on("join_dm")
    def handle_join_dm(data):
        user = _actor()
        if user is None:
            disconnect()
            return
        if not chat_rate_ok(user.id, event="join_dm"):
            emit("chat_error", {"error": "요청을 너무 빠르게 보냈습니다."})
            return
        room_id = _field(data, "room_id")
        room = chat_service.room_if_participant(room_id, user.id)
        if room is None:
            emit("chat_error", {"error": "접근할 수 없는 대화입니다."})
            return
        join_room(room.id)
        emit("dm_joined", {"room_id": room.id})

    @socketio.on("dm_message")
    def handle_dm_message(data):
        user = _actor()
        if user is None:
            disconnect()
            return
        if not chat_rate_ok(user.id):
            emit("chat_error", {"error": "메시지를 너무 빠르게 보냈습니다."})
            return
        room_id = _field(data, "room_id")
        content = _field(data, "content")
        try:
            message = chat_service.post_dm_message(user, room_id, content)
        except ValidationError as exc:
            emit("chat_error", {"error": str(exc)})
            return
        except (NotFound, Forbidden):
            # 미존재(404)·비참여(403) 등은 조용히 거부(대상 존재 여부 노출 최소화).
            emit("chat_error", {"error": "메시지를 보낼 수 없습니다."})
            return
        emit("dm_message", _serialize(message, user), to=message.dm_room_id)
