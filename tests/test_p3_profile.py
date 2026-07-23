"""P3 사용자 조회·마이페이지·소개글 수정 테스트.

- T-105 타인 프로필 조회 + 민감정보(password_hash 등) 비노출 (SR-02)
- T-106 소개글 XSS 입력이 렌더 시 이스케이프 (①/⑨)
- 소개글 수정/검증, 접근 제어(로그인 필요)
"""
from app.auth import service as auth_service
from app.extensions import db
from app.models import AuditLog, Product, User
from app.user import service as user_service


def _register(client, username, password="password123"):
    return client.post(
        "/register", data={"username": username, "password": password}
    )


def _login(client, username, password="password123"):
    return client.post("/login", data={"username": username, "password": password})


def test_me_requires_login(client):
    r = client.get("/me", follow_redirects=False)
    assert r.status_code in (302, 401)


def test_profile_requires_login(app, client):
    with app.app_context():
        u = auth_service.register_user("viewtarget", "password123")
        uid = u.id
    r = client.get(f"/users/{uid}", follow_redirects=False)
    assert r.status_code in (302, 401)


def test_update_bio_persists(app, client):
    _register(client, "biouser")
    _login(client, "biouser")
    r = client.post("/me", data={"bio": "안녕하세요 중고거래 좋아합니다"}, follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        u = User.query.filter_by(username="biouser").first()
        assert u.bio == "안녕하세요 중고거래 좋아합니다"
        audit = AuditLog.query.filter_by(
            action="update_bio", actor_id=u.id
        ).one()
        assert audit.actor_type == "user"


def test_bio_too_long_rejected(app, client):
    _register(client, "longbio")
    _login(client, "longbio")
    r = client.post("/me", data={"bio": "x" * 501})
    assert r.status_code == 400
    assert "최대 500자" in r.get_data(as_text=True)
    with app.app_context():
        u = User.query.filter_by(username="longbio").first()
        assert u.bio == ""  # 저장되지 않음
        assert (
            AuditLog.query.filter_by(action="update_bio", actor_id=u.id).count()
            == 0
        )


def test_me_post_requires_csrf(app, client):
    _register(client, "profile_csrf")
    _login(client, "profile_csrf")
    app.config["WTF_CSRF_ENABLED"] = True
    r = client.post("/me", data={"bio": "토큰 없는 변경"})
    assert r.status_code == 400
    assert User.query.filter_by(username="profile_csrf").one().bio == ""


def test_me_ignores_forged_target_id_and_updates_only_self(app, client):
    target = auth_service.register_user("profile_target", "password123")
    _register(client, "profile_owner")
    _login(client, "profile_owner")
    r = client.post(
        "/me",
        data={"bio": "본인 소개글", "user_id": target.id},
        follow_redirects=True,
    )
    assert r.status_code == 200
    assert User.query.filter_by(username="profile_owner").one().bio == "본인 소개글"
    assert User.query.filter_by(username="profile_target").one().bio == ""


def test_view_other_profile_hides_sensitive(app, client):
    with app.app_context():
        target = auth_service.register_user("target2", "password123")
        target.bio = "타겟 소개글"
        target.balance = 987654321
        target.failed_login_count = 4
        db.session.commit()
        tid, thash = target.id, target.password_hash
        assert set(user_service.public_profile(target)) == {
            "username",
            "bio",
            "created_at",
            "active_products",
        }
    _register(client, "viewer2")
    _login(client, "viewer2")
    r = client.get(f"/users/{tid}")
    assert r.status_code == 200
    assert "target2" in r.get_data(as_text=True)
    assert "타겟 소개글" in r.get_data(as_text=True)
    # 민감정보(비밀번호 해시)는 절대 노출되지 않아야 함
    assert thash not in r.get_data(as_text=True)
    assert "argon2" not in r.get_data(as_text=True)
    assert "987654321" not in r.get_data(as_text=True)


def test_bio_xss_is_escaped(app, client):
    _register(client, "xssuser")
    _login(client, "xssuser")
    payload = "<script>alert(1)</script>"
    client.post("/me", data={"bio": payload}, follow_redirects=True)
    with app.app_context():
        uid = User.query.filter_by(username="xssuser").first().id
    r = client.get(f"/users/{uid}")
    body = r.get_data(as_text=True)
    # 원문 스크립트 태그가 그대로 실행 가능한 형태로 들어가면 안 됨
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_profile_404_for_unknown_user(app, client):
    _register(client, "seeker")
    _login(client, "seeker")
    r = client.get("/users/nonexistent-id")
    assert r.status_code == 404


def test_profile_counts_only_active_products_of_active_seller(app, client):
    with app.app_context():
        seller = auth_service.register_user("seller_profile", "password123")
        db.session.add_all(
            [
                Product(
                    title="active item",
                    description="d",
                    price=100,
                    seller_id=seller.id,
                    status="active",
                ),
                Product(
                    title="blocked item",
                    description="d",
                    price=100,
                    seller_id=seller.id,
                    status="blocked",
                ),
            ]
        )
        db.session.commit()
        assert user_service.public_profile(seller)["active_products"] == 1
        seller.status = "dormant"
        db.session.commit()
        assert user_service.public_profile(seller)["active_products"] == 0
