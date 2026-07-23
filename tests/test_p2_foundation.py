"""P2 공통 보안 기반 테스트.

체크리스트/설계 매핑:
- T-902 보안 헤더(㉔)
- T-903 debug off·안전한 오류 처리(⑦㉖)  ← 여기서는 오류 헤더/일반화 확인
- 비밀번호 해시(③), 로그인/세션, 로그인 잠금(⑥)
- T-901 CSRF 미토큰 거부(②)
- ORM 제약(⑫, 설계 §5): 송금/신고/DM/상품 CHECK·UNIQUE
"""
import uuid

import pytest
from sqlalchemy.exc import IntegrityError

from app import create_app
from app.extensions import db
from app.models import User, Product, Report, DMRoom, Transfer, AuditLog
from app.auth import service


# ---------- 인프라/헤더 ----------

def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_security_headers(client):
    r = client.get("/")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("Referrer-Policy") == "no-referrer"
    assert "geolocation=()" in r.headers.get("Permissions-Policy", "")
    assert "Content-Security-Policy" in r.headers
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert "connect-src 'self'" in r.headers["Content-Security-Policy"]
    assert client.get("/login").headers.get("Cache-Control") == "no-store"


def test_internal_error_is_generic_and_debugger_is_disabled(app, caplog):
    app.config["PROPAGATE_EXCEPTIONS"] = False

    @app.get("/_test/boom")
    def _boom():
        raise RuntimeError("TOP_SECRET_INTERNAL_DETAIL")

    r = app.test_client().get("/_test/boom")
    assert r.status_code == 500
    assert b"TOP_SECRET_INTERNAL_DETAIL" not in r.data
    assert b"Traceback" not in r.data
    assert b"server error" not in r.data.lower()
    assert "Content-Security-Policy" in r.headers
    assert "TOP_SECRET_INTERNAL_DETAIL" not in caplog.text
    assert "RuntimeError" in caplog.text


def test_index_public_anonymous(client):
    # 익명 사용자도 홈 접근 가능(공개 경계)
    assert client.get("/").status_code == 200


def test_safe_environment_defaults(monkeypatch):
    dev_app = create_app("dev")
    assert dev_app.config["DEBUG"] is False
    assert dev_app.config["SOCKET_ALLOWED_ORIGINS"] is None
    assert dev_app.config["SECRET_KEY"] != "dev-only-insecure-key-change-me"

    with pytest.raises(RuntimeError):
        create_app("typo")

    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        create_app("prod")


def test_production_https_headers_and_secure_cookie(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "prod-test-secret-with-sufficient-randomness")
    prod_app = create_app("prod")
    r = prod_app.test_client().get("/login")
    assert r.status_code == 200
    assert "max-age=31536000" in r.headers["Strict-Transport-Security"]
    assert "Secure" in r.headers.get("Set-Cookie", "")


# ---------- 비밀번호 해시(V-02, ③) ----------

def test_password_is_hashed_not_plaintext(app):
    user = service.register_user("alice", "password123")
    assert user.password_hash != "password123"
    assert user.password_hash.startswith("$argon2")
    assert service.verify_password(user.password_hash, "password123") is True
    assert service.verify_password(user.password_hash, "wrong") is False


def test_weak_password_rejected(app):
    with pytest.raises(service.ValidationError):
        service.register_user("bob", "short")


def test_duplicate_username_rejected(app):
    service.register_user("carol", "password123")
    with pytest.raises(service.ValidationError):
        service.register_user("carol", "password123")


def test_unknown_username_still_runs_password_verification(app, monkeypatch):
    calls = []

    def fake_verify(password_hash, password):
        calls.append((password_hash, password))
        return False

    monkeypatch.setattr(service, "verify_password", fake_verify)
    result, user = service.attempt_login("does_not_exist", "password123")
    assert result == service.LoginResult.BAD_CREDENTIALS
    assert user is None
    assert calls == [(service._DUMMY_HASH, "password123")]


# ---------- 로그인/세션/잠금(⑥) ----------

def test_register_login_logout_flow(client, app):
    assert client.post(
        "/register", data={"username": "dave", "password": "password123"}
    ).status_code in (200, 302)
    r = client.post(
        "/login", data={"username": "dave", "password": "password123"}
    )
    assert r.status_code in (200, 302)
    # 보호된 페이지 접근 가능(세션 유지)
    assert client.get("/me/password").status_code == 200
    assert client.post("/logout").status_code == 302
    assert client.get("/me/password").status_code == 302


def test_login_cookie_is_permanent_and_hardened(client, app):
    service.register_user("cookie_user", "password123")
    r = client.post(
        "/login", data={"username": "cookie_user", "password": "password123"}
    )
    cookie = r.headers.get("Set-Cookie", "")
    assert "secure_coding_session=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    assert "Expires=" in cookie


def test_dormant_user_existing_session_is_invalidated(client, app):
    service.register_user("dormant_user", "password123")
    client.post(
        "/login", data={"username": "dormant_user", "password": "password123"}
    )
    user = User.query.filter_by(username="dormant_user").first()
    user.status = "dormant"
    db.session.commit()
    assert client.get("/me/password", follow_redirects=False).status_code == 302


def test_login_lockout_after_failures(client, app):
    service.register_user("erin", "password123")
    for _ in range(app.config["LOGIN_MAX_FAILURES"]):
        client.post("/login", data={"username": "erin", "password": "bad"})
    # 임계치 도달 후엔 올바른 비밀번호도 잠금으로 거부
    with app.app_context():
        user = User.query.filter_by(username="erin").first()
        assert user.locked_until is not None


def test_protected_route_requires_login(client):
    r = client.get("/me/password", follow_redirects=False)
    assert r.status_code in (302, 401)


# ---------- CSRF(②, T-901) ----------

def test_csrf_missing_token_rejected(app):
    app.config["WTF_CSRF_ENABLED"] = True
    c = app.test_client()
    r = c.post("/register", data={"username": "frank", "password": "password123"})
    assert r.status_code == 400  # CSRF 토큰 누락 거부


def test_authenticated_base_always_renders_logout_csrf(client, app):
    service.register_user("csrf_user", "password123")
    client.post("/login", data={"username": "csrf_user", "password": "password123"})
    app.config["WTF_CSRF_ENABLED"] = True
    r = client.get("/me/password")
    assert r.status_code == 200
    # 비밀번호 변경 폼 + 공통 내비게이션 로그아웃 폼
    assert r.data.count(b'name="csrf_token"') >= 2


# ---------- ORM 제약(설계 §5) ----------

def _mk_user(username):
    u = User(username=username, password_hash="x")
    db.session.add(u)
    db.session.commit()
    return u


def test_transfer_self_send_rejected(app):
    u = _mk_user("gina")
    db.session.add(
        Transfer(
            kind="transfer",
            sender_id=u.id,
            receiver_id=u.id,
            amount=10,
            idempotency_key=str(uuid.uuid4()),
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_transfer_amount_must_be_positive(app):
    a, b = _mk_user("h1"), _mk_user("h2")
    db.session.add(
        Transfer(
            kind="transfer",
            sender_id=a.id,
            receiver_id=b.id,
            amount=0,
            idempotency_key=str(uuid.uuid4()),
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_transfer_requires_idempotency_key(app):
    a, b = _mk_user("idem_a"), _mk_user("idem_b")
    db.session.add(
        Transfer(kind="transfer", sender_id=a.id, receiver_id=b.id, amount=10)
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_report_requires_exactly_one_target(app):
    reporter = _mk_user("ivan")
    target = _mk_user("judy")
    prod = Product(title="t", description="d", price=100, seller_id=target.id)
    db.session.add(prod)
    db.session.commit()
    # 둘 다 지정 → CHECK 위반
    db.session.add(
        Report(
            reporter_id=reporter.id,
            reported_user_id=target.id,
            reported_product_id=prod.id,
            reason="both",
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_report_duplicate_target_rejected(app):
    reporter = _mk_user("kate")
    target = _mk_user("liam")
    db.session.add(Report(reporter_id=reporter.id, reported_user_id=target.id, reason="a"))
    db.session.commit()
    db.session.add(Report(reporter_id=reporter.id, reported_user_id=target.id, reason="b"))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_report_self_user_rejected(app):
    reporter = _mk_user("self_reporter")
    db.session.add(
        Report(
            reporter_id=reporter.id,
            reported_user_id=reporter.id,
            reason="self",
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_report_resolved_requires_reviewer_and_timestamp(app):
    reporter = _mk_user("reporter2")
    target = _mk_user("target2")
    db.session.add(
        Report(
            reporter_id=reporter.id,
            reported_user_id=target.id,
            reason="resolved without review metadata",
            status="resolved",
            resolution="upheld",
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_dm_room_requires_ordered_pair(app):
    # 실제 사용자 2명(FK 충족) + 역순 삽입으로 CHECK(user_a_id < user_b_id) 위반 유도
    u1, u2 = _mk_user("na"), _mk_user("nb")
    hi, lo = sorted([u1.id, u2.id], reverse=True)
    db.session.add(DMRoom(user_a_id=hi, user_b_id=lo))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_product_price_must_be_positive(app):
    seller = _mk_user("mia")
    db.session.add(Product(title="t", description="d", price=-1, seller_id=seller.id))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_cli_initializes_db_and_creates_audited_admin(app, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-password-123")
    runner = app.test_cli_runner()
    assert runner.invoke(args=["init-db"]).exit_code == 0
    result = runner.invoke(args=["create-admin", "admin_user"])
    assert result.exit_code == 0
    admin = User.query.filter_by(username="admin_user").one()
    assert admin.role == "admin"
    assert service.verify_password(admin.password_hash, "admin-password-123")
    audit = AuditLog.query.filter_by(action="create_admin").one()
    assert audit.actor_type == "system"
    assert audit.actor_id is None


@pytest.mark.parametrize(
    ("actor_type", "with_actor"),
    [("system", True), ("user", False), ("admin", False)],
)
def test_audit_actor_type_and_id_must_match(app, actor_type, with_actor):
    actor = _mk_user(f"actor_{actor_type}")
    db.session.add(
        AuditLog(
            actor_type=actor_type,
            actor_id=actor.id if with_actor else None,
            action="invalid_actor_combination",
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()
