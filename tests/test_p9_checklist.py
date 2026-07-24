"""P9 — 공식 체크리스트 ①~㉗ 전수 점검 + 침투 테스트 (교차 관심사 통합 검증).

기능별 상세 검증은 test_p2~test_p8에 있고, 여기서는 체크리스트 항목을 한 곳에서
명시적으로 재확인하고(회귀 방지), 인증/권한 우회·주입·XSS·헤더 등 침투 관점을 모은다.
설계 §11의 항목 번호를 각 테스트에 매핑한다.
"""
from datetime import timedelta
import time
from pathlib import Path

import pytest
from flask import g
from sqlalchemy.exc import IntegrityError

from app.auth import service as auth_service
from app import security
from app.config import ProdConfig, BaseConfig
from app.extensions import db
from app.models import Product, User


# ---------- 헬퍼 ----------

def _register(client, username, password="password123"):
    return client.post("/register", data={"username": username, "password": password})


def _login(client, username, password="password123"):
    return client.post("/login", data={"username": username, "password": password})


def _auth(client, username):
    client.post("/logout")
    _register(client, username)
    _login(client, username)


def _uid(username):
    return User.query.filter_by(username=username).one().id


def _make_user(app, name, role="user", status="active"):
    with app.app_context():
        u = auth_service.register_user(name, "password123")
        u.role = role
        u.status = status
        db.session.commit()
        return u.id


# ---------- ① 회원가입 서버측 입력 검증 ----------

def test_registration_validates_username_and_password_boundaries(app):
    """① 사용자명 길이·허용문자와 비밀번호 길이를 서비스 경계에서 검증한다."""
    invalid_pairs = [
        ("ab", "password123"),            # 사용자명 너무 짧음
        ("a" * 21, "password123"),        # 사용자명 너무 김
        ("bad-name", "password123"),      # 허용하지 않은 '-'
        ("<script>", "password123"),      # 태그/특수문자
        ("valid_user", "short"),          # 비밀번호 너무 짧음
        ("valid_user", "p" * 129),        # 비밀번호 너무 김
    ]
    with app.app_context():
        for username, password in invalid_pairs:
            with pytest.raises(auth_service.ValidationError):
                auth_service.register_user(username, password)
        assert User.query.count() == 0


# ---------- ④ 세션 쿠키 · ⑤ 세션 만료 ----------

def test_session_cookie_flags(app, client):
    """④ 세션 쿠키 HttpOnly·SameSite. 운영은 Secure=True."""
    _register(client, "cookie_u")
    resp = _login(client, "cookie_u")
    session_cookies = [
        h for h in resp.headers.getlist("Set-Cookie")
        if h.startswith(app.config["SESSION_COOKIE_NAME"] + "=")
    ]
    assert session_cookies, "세션 쿠키가 설정되어야 한다"
    cookie = session_cookies[0]
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    # 개발/테스트는 로컬 HTTP라 Secure 미설정, 운영(prod)에서 True.
    assert ProdConfig.SESSION_COOKIE_SECURE is True


def test_session_lifetime_and_expired_session_is_rejected(app, client):
    """⑤ 세션 수명 설정 + 만료된 세션의 보호 경로 접근 거부."""
    assert isinstance(BaseConfig.PERMANENT_SESSION_LIFETIME, timedelta)
    assert BaseConfig.PERMANENT_SESSION_LIFETIME.total_seconds() > 0
    _auth(client, "expired_u")
    assert client.get("/me/password").status_code == 200
    # 기존 쿠키를 즉시 만료된 것으로 판정하게 해 서버측 만료 검사를 실증한다.
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=0)
    time.sleep(1.1)  # itsdangerous 타임스탬프는 초 단위다.
    # 공용 fixture의 열린 app_context가 Flask-Login 사용자를 g에 캐시하므로
    # 운영 요청처럼 다음 요청에서 쿠키를 다시 읽도록 테스트 캐시를 비운다.
    g.pop("_login_user", None)
    assert client.get(
        "/me/password", follow_redirects=False
    ).status_code == 302


def test_password_change_requires_current_password(app, client):
    """⑤ 비밀번호 변경 시 현재 비밀번호 재확인(재인증). 틀리면 거부·미변경."""
    _auth(client, "reauth_u")
    r = client.post("/me/password", data={
        "current_password": "wrong-password",
        "new_password": "newpassword123",
    })
    assert r.status_code == 400
    # 기존 비밀번호로 여전히 로그인 가능(변경 안 됨)
    client.post("/logout")
    assert _login(client, "reauth_u", "password123").status_code == 302


# ---------- ⑦ ㉖ 오류 처리(스택트레이스·내부정보 미노출) ----------

@pytest.mark.parametrize("path", ["/no-such-page", "/products/does-not-exist"])
def test_error_pages_leak_no_internals(app, client, path):
    body = client.get(path).get_data(as_text=True)
    assert "Traceback" not in body
    assert "werkzeug" not in body.lower()
    assert "sqlalchemy" not in body.lower()


# ---------- ⑨ ㉔ 보안 헤더 · XSS ----------

def test_security_headers_present(app, client):
    """㉔ 보안 헤더 일괄 적용."""
    h = client.get("/").headers
    assert "default-src 'self'" in h.get("Content-Security-Policy", "")
    assert "script-src 'self'" in h.get("Content-Security-Policy", "")
    assert h.get("X-Frame-Options") == "DENY"
    assert h.get("X-Content-Type-Options") == "nosniff"
    assert h.get("Referrer-Policy") == "no-referrer"
    assert "Permissions-Policy" in h


def test_stored_xss_in_bio_is_escaped(app, client):
    """⑨ 소개글에 스크립트 페이로드 저장 후 조회 시 이스케이프."""
    _auth(client, "xss_bio")
    payload = "<script>alert('x')</script>"
    client.post("/me", data={"bio": payload})
    with app.app_context():
        uid = _uid("xss_bio")
    body = client.get(f"/users/{uid}").get_data(as_text=True)
    assert "<script>alert('x')</script>" not in body
    assert "&lt;script&gt;" in body


def test_stored_xss_in_product_is_escaped(app, client):
    """⑨ 상품 제목/설명 스크립트 페이로드 이스케이프."""
    _auth(client, "xss_prod")
    client.post("/products/new", data={
        "title": "정상제목", "description": "<img src=x onerror=alert(1)>", "price": "1000",
    })
    with app.app_context():
        pid = Product.query.filter_by(title="정상제목").one().id
    body = client.get(f"/products/{pid}").get_data(as_text=True)
    assert "<img src=x onerror=alert(1)>" not in body
    assert "&lt;img" in body


def test_chat_client_uses_text_content_for_untrusted_messages():
    """⑨⑬ 실시간 수신 메시지를 HTML이 아닌 텍스트로만 렌더링한다."""
    script = (
        Path(__file__).parents[1] / "app" / "static" / "js" / "chat.js"
    ).read_text(encoding="utf-8")
    assert "text.textContent = msg.content" in script
    assert "user.textContent = msg.username" in script
    assert ".innerHTML" not in script


# ---------- ⑧ ⑫ 입력 검증 · 데이터 무결성 ----------

@pytest.mark.parametrize("price", ["0", "-100", "abc", "1.5", "9999999999999"])
def test_price_validation_rejected(app, client, price):
    """⑧ 가격 정수·범위 검증."""
    _auth(client, f"price_{abs(hash(price)) % 10000}")
    r = client.post("/products/new", data={
        "title": "가격검증", "description": "d", "price": price,
    })
    assert r.status_code == 400


def test_db_check_constraints_reject_bad_data(app):
    """⑫ ORM/DB 제약이 잘못된 형식 저장을 거부한다."""
    with app.app_context():
        # 잘못된 status
        db.session.add(User(username="bad_status", password_hash="x", status="ghost"))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()
        # 잘못된 role
        db.session.add(User(username="bad_role", password_hash="x", role="superuser"))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()
        # 가격 범위 위반
        seller = auth_service.register_user("integ_seller", "password123")
        db.session.add(Product(title="t", description="d", price=0, seller_id=seller.id))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


def test_posix_private_modes_are_applied_to_sqlite_and_instance(monkeypatch):
    """㉓ SQLite 파일 0600·instance/uploads 디렉터리 0700 적용 로직."""
    calls = []
    monkeypatch.setattr(
        security.os, "chmod", lambda path, mode: calls.append((str(path), mode))
    )

    class FakeCursor:
        def execute(self, statement):
            assert statement == "PRAGMA database_list"
            return self

        @staticmethod
        def fetchall():
            return [(0, "main", "/srv/app/instance/market.db")]

    security._harden_sqlite_database_files(FakeCursor(), platform="posix")
    assert calls == [("/srv/app/instance/market.db", 0o600)]
    assert security.set_private_mode(
        "/srv/app/instance", 0o700, platform="posix"
    )
    assert calls[-1] == ("/srv/app/instance", 0o700)
    assert security.set_private_mode(
        "C:/app/instance/market.db", 0o600, platform="nt"
    ) is False


# ---------- ㉒ 파라미터 바인딩 · SQLi 방지 ----------

def test_sort_field_injection_is_neutralized(app, client):
    """㉒ 정렬 필드 허용목록 — 주입값은 기본값으로 정규화, 오류·주입 없음."""
    with app.app_context():
        seller = auth_service.register_user("p9_sort_seller", "password123")
        db.session.add(Product(
            title="P9 정렬 상품", description="d", price=100,
            seller_id=seller.id,
        ))
        db.session.commit()
    r = client.get("/products?sort=price%3BDROP%20TABLE%20user")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "P9 정렬 상품" in body
    assert '<option value="newest" selected>' in body
    assert "DROP TABLE" not in body
    with app.app_context():
        assert User.query.filter_by(username="p9_sort_seller").one()


def test_search_sql_metacharacters_are_safe(app, client):
    """㉒ 검색어의 SQL 메타문자는 파라미터 바인딩으로 안전 처리."""
    with app.app_context():
        seller = auth_service.register_user("p9_sqli_seller", "password123")
        db.session.add(Product(
            title="SQLi로 노출되면 안 되는 상품",
            description="ordinary", price=100, seller_id=seller.id,
        ))
        db.session.commit()
    r = client.get("/products/search?q=%27%20OR%20%271%27%3D%271")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "SQLi로 노출되면 안 되는 상품" not in body
    assert "Traceback" not in body


# ---------- ⑩ ⑪ SR-02 인증·권한 우회(침투) ----------

ADMIN_GET = [
    "/admin", "/admin/users", "/admin/products",
    "/admin/reports", "/admin/logs", "/admin/transactions",
]
LOGIN_GET = ["/wallet", "/chat"]


@pytest.mark.parametrize("path", ADMIN_GET)
def test_admin_routes_reject_anonymous_and_normal(app, client, path):
    # 익명 → 로그인 리다이렉트
    assert client.get(path, follow_redirects=False).status_code in (302, 401)
    # 일반 사용자 → 403
    _auth(client, "fb_user")
    assert client.get(path).status_code == 403


def test_admin_post_forbidden_for_normal_user(app, client):
    victim = _make_user(app, "fb_victim")
    _auth(client, "fb_attacker")
    assert client.post(f"/admin/users/{victim}/dormant").status_code == 403
    with app.app_context():
        assert db.session.get(User, victim).status == "active"


@pytest.mark.parametrize("path", LOGIN_GET)
def test_login_required_routes_reject_anonymous(app, client, path):
    assert client.get(path, follow_redirects=False).status_code in (302, 401)


def test_idor_cannot_edit_others_product(app, client):
    """⑪ 소유자 아닌 사용자의 상품 수정·삭제 차단(IDOR)."""
    _auth(client, "owner_u")
    client.post("/products/new", data={"title": "내상품", "description": "d", "price": "500"})
    with app.app_context():
        pid = Product.query.filter_by(title="내상품").one().id
    _auth(client, "attacker_u")
    assert client.get(f"/products/{pid}/edit").status_code == 403
    assert client.post(f"/products/{pid}/delete").status_code == 403
    with app.app_context():
        assert db.session.get(Product, pid).status == "active"


# ---------- ㉗ 의존성 관리(버전 고정) ----------

def test_requirements_are_pinned():
    """㉗ 의존성 버전 고정(재현성). 모든 요구사항 라인이 == 로 고정."""
    req = Path(__file__).resolve().parent.parent / "requirements.txt"
    lines = [
        ln.strip() for ln in req.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    assert lines, "requirements.txt 가 비어있지 않아야 한다"
    for ln in lines:
        assert "==" in ln, f"고정되지 않은 의존성: {ln}"
