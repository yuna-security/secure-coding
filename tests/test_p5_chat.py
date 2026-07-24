"""P5 채팅 테스트 (R3).

체크리스트/설계 매핑:
- AC3.1 전체 실시간 채팅  - AC3.2 1:1 DM(참여자만)  - AC3.3/V-05 발신자=서버 세션
- ⑬⑮ 메시지 길이·내용 서버측 검증  - ⑭ Socket 인증(미인증 연결 거부)
- ⑯ 사용자별 이벤트 Rate Limit
"""
import hashlib
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import Forbidden

from app import create_app
from app.admin import service as admin_service
from app.auth import service as auth_service
from app.extensions import db, socketio
from app.chat import service as chat_service
from app.chat.connections import reset_connections
from app.chat.ratelimit import chat_limiter
from app.models import ChatMessage, DMRoom, User
from app.report import service as report_service


# Socket.IO 핸들러는 이벤트마다 자체 요청 컨텍스트에서 세션을 로드한다.
# conftest의 app 픽스처는 테스트 전체 동안 app_context를 열어두는데, 그 상태에서는
# 소켓 연결의 세션 로딩이 깨진다(운영에는 없는 테스트 아티팩트). 여기서는 컨텍스트를
# 열어두지 않는 app 픽스처로 오버라이드한다. 인메모리 DB는 StaticPool로 공유되어
# with app.app_context() 재진입 간에도 데이터가 유지된다.
@pytest.fixture
def app():
    app = create_app("test")
    with app.app_context():
        db.create_all()
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()
    chat_limiter.reset()
    reset_connections()


# ---------- 헬퍼 ----------

def _client_for(app, username, password="password123"):
    c = app.test_client()
    c.post("/register", data={"username": username, "password": password})
    c.post("/login", data={"username": username, "password": password})
    return c


def _uid(username):
    return User.query.filter_by(username=username).one().id


def _make_user(app, name, status="active"):
    with app.app_context():
        u = auth_service.register_user(name, "password123")
        if status != "active":
            u.status = status
            db.session.commit()
        return u.id


def _sio(app, flask_client):
    return socketio.test_client(app, flask_test_client=flask_client)


# ---------- HTTP 라우트 ----------

def test_chat_requires_login(app, client):
    assert client.get("/chat", follow_redirects=False).status_code in (302, 401)


def test_chat_page_renders(app):
    c = _client_for(app, "chat_viewer")
    r = c.get("/chat")
    assert r.status_code == 200 and "전체 채팅" in r.get_data(as_text=True)


def test_socket_origin_policy_rejects_cross_origin(app):
    c = app.test_client()
    endpoint = "/socket.io/?EIO=4&transport=polling"
    assert c.get(endpoint, headers={"Origin": "http://localhost"}).status_code == 200
    assert (
        c.get(endpoint, headers={"Origin": "https://evil.example"}).status_code
        == 400
    )


def test_dm_requires_login(app, client):
    tid = _make_user(app, "dm_target1")
    assert client.get(f"/chat/dm/{tid}", follow_redirects=False).status_code in (302, 401)


def test_dm_self_redirects(app):
    c = _client_for(app, "dm_self")
    with app.app_context():
        uid = _uid("dm_self")
    r = c.get(f"/chat/dm/{uid}", follow_redirects=False)
    assert r.status_code == 302
    with app.app_context():
        assert DMRoom.query.count() == 0


def test_dm_unknown_or_dormant_404(app):
    dormant = _make_user(app, "dm_dormant", status="dormant")
    c = _client_for(app, "dm_seeker")
    assert c.get(f"/chat/dm/{dormant}").status_code == 404
    assert c.get("/chat/dm/nope").status_code == 404
    with app.app_context():
        assert DMRoom.query.count() == 0


def test_dm_creates_room_once(app):
    other = _make_user(app, "dm_other")
    c = _client_for(app, "dm_me")
    assert c.get(f"/chat/dm/{other}").status_code == 200
    assert c.get(f"/chat/dm/{other}").status_code == 200
    with app.app_context():
        assert DMRoom.query.count() == 1
        room = DMRoom.query.one()
        assert room.user_a_id < room.user_b_id  # 정규화 확인


# ---------- Socket 인증 (⑭) ----------

def test_socket_rejects_unauthenticated(app, client):
    sio = _sio(app, client)  # 로그인하지 않은 클라이언트
    assert not sio.is_connected()


def test_socket_accepts_authenticated(app):
    c = _client_for(app, "sock_ok")
    sio = _sio(app, c)
    assert sio.is_connected()
    sio.disconnect()


def test_socket_rejects_dormant_after_login(app):
    """세션이 살아 있어도 휴면 전환된 계정은 소켓 연결이 거부된다(_actor 재검증)."""
    c = _client_for(app, "sock_dormant")
    with app.app_context():
        u = User.query.filter_by(username="sock_dormant").one()
        u.status = "dormant"
        db.session.commit()
    sio = _sio(app, c)
    assert not sio.is_connected()


def test_connected_socket_is_dropped_when_user_becomes_dormant(app):
    c = _client_for(app, "sock_live_dormant")
    sio = _sio(app, c)
    assert sio.is_connected()

    with app.app_context():
        target = User.query.filter_by(username="sock_live_dormant").one()
        admin = auth_service.register_user("sock_admin", "password123")
        admin.role = "admin"
        db.session.commit()
        admin_service.set_user_dormant(admin, target.id)

    assert not sio.is_connected()


def test_auto_dormancy_disconnects_existing_socket(app):
    c = _client_for(app, "sock_auto_dormant")
    sio = _sio(app, c)
    assert sio.is_connected()

    with app.app_context():
        target_id = _uid("sock_auto_dormant")
        reporters = [
            auth_service.register_user(f"sock_reporter_{i}", "password123")
            for i in range(3)
        ]
        for reporter in reporters:
            report_service.report_user(reporter, target_id, "자동 휴면 검증")

    assert not sio.is_connected()


def test_logout_disconnects_existing_socket(app):
    c = _client_for(app, "sock_logout")
    sio = _sio(app, c)
    assert sio.is_connected()
    assert c.post("/logout").status_code == 302
    assert not sio.is_connected()


# ---------- 전체 채팅 (AC3.1) ----------

def test_global_message_broadcast_and_persist(app):
    c = _client_for(app, "g_sender")
    sio = _sio(app, c)
    sio.emit("global_message", {"content": "안녕하세요"})
    received = sio.get_received()
    names = [r["name"] for r in received]
    assert "global_message" in names
    payload = next(r["args"][0] for r in received if r["name"] == "global_message")
    assert payload["content"] == "안녕하세요"
    with app.app_context():
        msg = ChatMessage.query.filter_by(scope="global").one()
        assert msg.content == "안녕하세요"
        assert msg.sender_id == _uid("g_sender")
    sio.disconnect()


def test_global_sender_is_server_session_not_client(app):
    """클라이언트가 보낸 username/sender_id를 신뢰하지 않는다(V-05)."""
    c = _client_for(app, "g_real")
    sio = _sio(app, c)
    sio.emit("global_message", {
        "content": "위조 시도",
        "username": "hacker",
        "sender_id": "forged-id",
    })
    sio.get_received()
    with app.app_context():
        msg = ChatMessage.query.filter_by(scope="global").one()
        assert msg.sender_id == _uid("g_real")  # 세션 사용자
    sio.disconnect()


def test_global_empty_message_rejected(app):
    c = _client_for(app, "g_empty")
    sio = _sio(app, c)
    sio.emit("global_message", {"content": "   "})
    names = [r["name"] for r in sio.get_received()]
    assert "chat_error" in names
    with app.app_context():
        assert ChatMessage.query.count() == 0
    sio.disconnect()


def test_global_too_long_message_rejected(app):
    c = _client_for(app, "g_long")
    sio = _sio(app, c)
    sio.emit("global_message", {"content": "x" * 501})
    names = [r["name"] for r in sio.get_received()]
    assert "chat_error" in names
    with app.app_context():
        assert ChatMessage.query.count() == 0
    sio.disconnect()


@pytest.mark.parametrize("payload", ["문자열", ["content", "배열"], 123])
def test_global_non_object_payload_rejected_without_server_error(app, payload):
    c = _client_for(app, f"g_shape_{type(payload).__name__}")
    sio = _sio(app, c)
    sio.emit("global_message", payload)
    names = [r["name"] for r in sio.get_received()]
    assert "chat_error" in names
    assert sio.is_connected()
    with app.app_context():
        assert ChatMessage.query.count() == 0
    sio.disconnect()


def test_global_rate_limited(app):
    chat_limiter.reset()
    c = _client_for(app, "g_flood")
    sio = _sio(app, c)
    for i in range(5):
        sio.emit("global_message", {"content": f"msg{i}"})
    sio.emit("global_message", {"content": "초과"})
    names = [r["name"] for r in sio.get_received()]
    assert "chat_error" in names
    with app.app_context():
        # 5개만 저장(임계 초과분은 거부)
        assert ChatMessage.query.filter_by(scope="global").count() == 5
    sio.disconnect()


def test_chat_content_database_constraint(app):
    with app.app_context():
        user = auth_service.register_user("chat_db_guard", "password123")
        for invalid in ("   ", "x" * 501):
            db.session.add(
                ChatMessage(
                    scope="global",
                    sender_id=user.id,
                    content=invalid,
                )
            )
            with pytest.raises(IntegrityError):
                db.session.commit()
            db.session.rollback()


def test_service_rejects_dormant_sender(app):
    with app.app_context():
        user = auth_service.register_user("chat_dormant_service", "password123")
        user.status = "dormant"
        db.session.commit()
        with pytest.raises(Forbidden):
            chat_service.post_global_message(user, "보내면 안 됨")
        assert ChatMessage.query.count() == 0


# ---------- 1:1 DM (AC3.2 / §7) ----------

def _dm_room_between(app, client_a, name_a, name_b):
    other_id = _make_user(app, name_b)
    ca = _client_for(app, name_a)
    ca.get(f"/chat/dm/{other_id}")  # 방 생성
    with app.app_context():
        room = DMRoom.query.one()
        return ca, other_id, room.id


def test_dm_message_delivered_to_participants(app):
    b_id = _make_user(app, "dm_b")
    ca = _client_for(app, "dm_a")
    ca.get(f"/chat/dm/{b_id}")
    with app.app_context():
        room_id = DMRoom.query.one().id

    cb = app.test_client()
    cb.post("/login", data={"username": "dm_b", "password": "password123"})

    sio_a = _sio(app, ca)
    sio_b = _sio(app, cb)
    sio_a.emit("join_dm", {"room_id": room_id})
    sio_b.emit("join_dm", {"room_id": room_id})
    sio_a.get_received(); sio_b.get_received()

    sio_a.emit("dm_message", {"room_id": room_id, "content": "비밀 메시지"})
    got_b = [r for r in sio_b.get_received() if r["name"] == "dm_message"]
    assert got_b and got_b[0]["args"][0]["content"] == "비밀 메시지"
    with app.app_context():
        msg = ChatMessage.query.filter_by(scope="dm").one()
        assert msg.dm_room_id == room_id and msg.sender_id == _uid("dm_a")
    sio_a.disconnect(); sio_b.disconnect()


def test_dm_non_participant_cannot_join(app):
    b_id = _make_user(app, "dmp_b")
    ca = _client_for(app, "dmp_a")
    ca.get(f"/chat/dm/{b_id}")
    with app.app_context():
        room_id = DMRoom.query.one().id

    cc = _client_for(app, "dmp_intruder")
    sio_c = _sio(app, cc)
    sio_c.emit("join_dm", {"room_id": room_id})
    names = [r["name"] for r in sio_c.get_received()]
    assert "chat_error" in names and "dm_joined" not in names
    sio_c.disconnect()


def test_dm_non_participant_cannot_send(app):
    b_id = _make_user(app, "dms_b")
    ca = _client_for(app, "dms_a")
    ca.get(f"/chat/dm/{b_id}")
    with app.app_context():
        room_id = DMRoom.query.one().id

    cc = _client_for(app, "dms_intruder")
    sio_c = _sio(app, cc)
    sio_c.emit("dm_message", {"room_id": room_id, "content": "침입"})
    names = [r["name"] for r in sio_c.get_received()]
    assert "chat_error" in names
    with app.app_context():
        assert ChatMessage.query.filter_by(scope="dm").count() == 0
    sio_c.disconnect()


def test_dm_non_participant_does_not_receive(app):
    b_id = _make_user(app, "dmr_b")
    ca = _client_for(app, "dmr_a")
    ca.get(f"/chat/dm/{b_id}")
    with app.app_context():
        room_id = DMRoom.query.one().id

    cb = app.test_client()
    cb.post("/login", data={"username": "dmr_b", "password": "password123"})
    cc = _client_for(app, "dmr_outsider")

    sio_a = _sio(app, ca)
    sio_b = _sio(app, cb)
    sio_c = _sio(app, cc)
    sio_a.emit("join_dm", {"room_id": room_id})
    sio_b.emit("join_dm", {"room_id": room_id})
    sio_c.emit("join_dm", {"room_id": room_id})  # 거부됨
    sio_a.get_received(); sio_b.get_received(); sio_c.get_received()

    sio_a.emit("dm_message", {"room_id": room_id, "content": "엿듣기 금지"})
    assert not [r for r in sio_c.get_received() if r["name"] == "dm_message"]
    assert [r for r in sio_b.get_received() if r["name"] == "dm_message"]
    sio_a.disconnect(); sio_b.disconnect(); sio_c.disconnect()


def test_join_dm_is_rate_limited_per_user(app):
    b_id = _make_user(app, "dm_join_limit_b")
    ca = _client_for(app, "dm_join_limit_a")
    ca.get(f"/chat/dm/{b_id}")
    with app.app_context():
        room_id = DMRoom.query.one().id

    sio = _sio(app, ca)
    for _ in range(6):
        sio.emit("join_dm", {"room_id": room_id})
    received = sio.get_received()
    assert len([r for r in received if r["name"] == "dm_joined"]) == 5
    assert [r for r in received if r["name"] == "chat_error"]
    sio.disconnect()


def test_dm_send_stops_when_other_participant_is_dormant(app):
    b_id = _make_user(app, "dm_dormant_peer_b")
    ca = _client_for(app, "dm_dormant_peer_a")
    ca.get(f"/chat/dm/{b_id}")
    with app.app_context():
        room_id = DMRoom.query.one().id
        other = db.session.get(User, b_id)
        other.status = "dormant"
        db.session.commit()

    sio = _sio(app, ca)
    sio.emit("dm_message", {"room_id": room_id, "content": "전송 금지"})
    assert [r for r in sio.get_received() if r["name"] == "chat_error"]
    with app.app_context():
        assert ChatMessage.query.filter_by(scope="dm").count() == 0
    sio.disconnect()


def test_dm_non_object_payload_rejected_without_server_error(app):
    b_id = _make_user(app, "dm_shape_b")
    ca = _client_for(app, "dm_shape_a")
    ca.get(f"/chat/dm/{b_id}")
    sio = _sio(app, ca)
    sio.emit("join_dm", ["not", "an", "object"])
    assert [r for r in sio.get_received() if r["name"] == "chat_error"]
    assert sio.is_connected()
    sio.disconnect()


def test_browser_client_filters_events_by_scope_and_waits_for_dm_join():
    script = (
        Path(__file__).parents[1] / "app" / "static" / "js" / "chat.js"
    ).read_text(encoding="utf-8")
    assert 'if (scope === "global")' in script
    assert 'else if (scope === "dm")' in script
    assert 'socket.on("dm_joined"' in script
    assert "if (!ready) return;" in script


def test_vendored_socketio_is_pinned_official_build():
    asset = (
        Path(__file__).parents[1]
        / "app"
        / "static"
        / "js"
        / "socket.io.min.js"
    )
    data = asset.read_bytes()
    assert len(data) == 46_831
    assert b"Socket.IO v4.8.1" in data[:100]
    assert hashlib.sha256(data).hexdigest() == (
        "b0e735814f8dcfecd6cdb8a7ce95a297"
        "a7e1e5f2727a29e6f5901801d52fa0c5"
    )
