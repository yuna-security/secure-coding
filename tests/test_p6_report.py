"""P6 신고·차단 테스트 (R4).

체크리스트/설계 매핑:
- ⑱ 사유 서버측 검증  - ⑲ 로그인 필요  - ⑳ 감사 로그
- ㉑/SR-04 자기·중복 신고 차단, 활성 신고자만 집계, 임계치 자동 조치·복구 대상
- AC4.3 상품 자동 차단  - AC4.4 사용자 자동 휴면
"""
from datetime import datetime, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app import create_app
from app.auth import service as auth_service
from app.config import TestConfig
from app.extensions import db, limiter
from app.models import AuditLog, Product, Report, User
from app.report import service as report_service


# ---------- 헬퍼 ----------

def _register(client, username, password="password123"):
    return client.post("/register", data={"username": username, "password": password})


def _login(client, username, password="password123"):
    return client.post("/login", data={"username": username, "password": password})


def _logout(client):
    client.post("/logout")


def _auth(client, username):
    _logout(client)
    _register(client, username)
    _login(client, username)


def _uid(username):
    return User.query.filter_by(username=username).one().id


def _make_seller_and_product(app, seller_name="seller", title="신고대상", status="active"):
    with app.app_context():
        seller = auth_service.register_user(seller_name, "password123")
        product = Product(
            title=title, description="d", price=100, seller_id=seller.id, status=status
        )
        db.session.add(product)
        db.session.commit()
        return seller.id, product.id


# ---------- 상품 신고 ----------

def test_report_requires_login(app, client):
    _, pid = _make_seller_and_product(app)
    r = client.post(f"/products/{pid}/report", data={"reason": "x"}, follow_redirects=False)
    assert r.status_code in (302, 401)
    with app.app_context():
        assert Report.query.count() == 0


def test_report_product_success(app, client):
    _, pid = _make_seller_and_product(app)
    _auth(client, "rp_reporter")
    r = client.post(f"/products/{pid}/report", data={"reason": "가짜 상품입니다"})
    assert r.status_code == 302
    with app.app_context():
        rep = Report.query.filter_by(reported_product_id=pid).one()
        assert rep.status == "pending" and rep.reason == "가짜 상품입니다"
        assert rep.reported_user_id is None
        assert AuditLog.query.filter_by(action="report_product", target=pid).count() == 1
        assert db.session.get(Product, pid).status == "active"


def test_self_report_product_rejected(app, client):
    _auth(client, "selfrep")
    with app.app_context():
        uid = _uid("selfrep")
        product = Product(title="내상품", description="d", price=100, seller_id=uid)
        db.session.add(product)
        db.session.commit()
        pid = product.id
    r = client.post(f"/products/{pid}/report", data={"reason": "사유"})
    assert r.status_code == 400
    with app.app_context():
        assert Report.query.count() == 0


def test_duplicate_product_report_rejected(app, client):
    _, pid = _make_seller_and_product(app)
    _auth(client, "dup_rep")
    assert client.post(f"/products/{pid}/report", data={"reason": "1차"}).status_code == 302
    assert client.post(f"/products/{pid}/report", data={"reason": "2차"}).status_code == 400
    with app.app_context():
        assert Report.query.filter_by(reported_product_id=pid).count() == 1


def test_report_hidden_or_unknown_product_404(app, client):
    _, active_pid = _make_seller_and_product(app, seller_name="hv_seller", title="active")
    _, blocked_pid = _make_seller_and_product(
        app, seller_name="hv_seller2", title="blocked", status="blocked"
    )
    _, deleted_pid = _make_seller_and_product(
        app, seller_name="hv_seller3", title="deleted", status="deleted"
    )
    _auth(client, "hv_reporter")
    assert client.post(f"/products/{blocked_pid}/report", data={"reason": "x"}).status_code == 404
    assert client.post(f"/products/{deleted_pid}/report", data={"reason": "x"}).status_code == 404
    assert client.post("/products/unknown-id/report", data={"reason": "x"}).status_code == 404
    with app.app_context():
        assert Report.query.count() == 0


def test_report_reason_required_and_maxlength(app, client):
    _, pid = _make_seller_and_product(app)
    _auth(client, "reason_rep")
    assert client.post(f"/products/{pid}/report", data={"reason": ""}).status_code == 400
    assert client.post(f"/products/{pid}/report", data={"reason": "x" * 1001}).status_code == 400
    with app.app_context():
        assert Report.query.count() == 0


def test_threshold_auto_blocks_product(app, client):
    _, pid = _make_seller_and_product(app, seller_name="th_seller", title="임계상품")
    for i in range(3):
        _auth(client, f"th_rep{i}")
        client.post(f"/products/{pid}/report", data={"reason": f"사유{i}"})
    with app.app_context():
        assert db.session.get(Product, pid).status == "blocked"
        assert (
            Report.query.filter_by(reported_product_id=pid, status="auto_actioned").count()
            == 3
        )
        audit = AuditLog.query.filter_by(
            action="product_auto_block",
            target=pid,
        ).one()
        assert audit.actor_type == "system"
        assert audit.actor_id is None
    _auth(client, "th_viewer")
    assert client.get(f"/products/{pid}").status_code == 404
    assert "임계상품" not in client.get("/products").get_data(as_text=True)


def test_dormant_reporters_not_counted(app, client):
    _, pid = _make_seller_and_product(app, seller_name="dn_seller", title="휴면집계")
    _auth(client, "dn1")
    client.post(f"/products/{pid}/report", data={"reason": "1"})
    _auth(client, "dn2")
    client.post(f"/products/{pid}/report", data={"reason": "2"})
    with app.app_context():
        u = User.query.filter_by(username="dn1").one()
        u.status = "dormant"
        db.session.commit()
    _auth(client, "dn3")
    client.post(f"/products/{pid}/report", data={"reason": "3"})
    with app.app_context():
        # 활성 신고자: dn2, dn3 = 2 < 3 → 아직 차단 아님
        assert db.session.get(Product, pid).status == "active"
    _auth(client, "dn4")
    client.post(f"/products/{pid}/report", data={"reason": "4"})
    with app.app_context():
        # 활성 신고자: dn2, dn3, dn4 = 3 → 차단
        assert db.session.get(Product, pid).status == "blocked"


def test_resolved_reports_are_not_reused_for_new_threshold(app, client):
    with app.app_context():
        seller = auth_service.register_user("resolved_seller", "password123")
        reviewer = User(
            username="resolved_admin",
            password_hash=auth_service.hash_password("password123"),
            role="admin",
        )
        old_reporters = [
            auth_service.register_user(f"resolved_old{i}", "password123")
            for i in range(2)
        ]
        product = Product(
            title="복구된 상품",
            description="d",
            price=100,
            seller_id=seller.id,
        )
        db.session.add_all([reviewer, product])
        db.session.flush()
        reviewed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.session.add_all(
            [
                Report(
                    reporter_id=reporter.id,
                    reported_product_id=product.id,
                    reason="과거 신고",
                    status="resolved",
                    resolution="reversed",
                    reviewed_by=reviewer.id,
                    reviewed_at=reviewed_at,
                )
                for reporter in old_reporters
            ]
        )
        db.session.commit()
        product_id = product.id

    _auth(client, "resolved_new")
    assert (
        client.post(
            f"/products/{product_id}/report",
            data={"reason": "새 신고"},
        ).status_code
        == 302
    )
    with app.app_context():
        assert db.session.get(Product, product_id).status == "active"
        assert (
            Report.query.filter_by(
                reported_product_id=product_id,
                status="pending",
            ).count()
            == 1
        )


def test_report_product_requires_csrf(app, client):
    _, pid = _make_seller_and_product(app, seller_name="cs_seller")
    _auth(client, "cs_rep")
    app.config["WTF_CSRF_ENABLED"] = True
    r = client.post(f"/products/{pid}/report", data={"reason": "x"})
    assert r.status_code == 400
    with app.app_context():
        assert Report.query.count() == 0


# ---------- 사용자 신고 ----------

def test_report_user_success(app, client):
    with app.app_context():
        target = auth_service.register_user("ru_target", "password123")
        tid = target.id
    _auth(client, "ru_reporter")
    r = client.post(f"/users/{tid}/report", data={"reason": "사기 사용자"})
    assert r.status_code == 302
    with app.app_context():
        rep = Report.query.filter_by(reported_user_id=tid).one()
        assert rep.status == "pending" and rep.reported_product_id is None
        assert AuditLog.query.filter_by(action="report_user", target=tid).count() == 1
        assert db.session.get(User, tid).status == "active"


def test_self_report_user_rejected(app, client):
    _auth(client, "self_user")
    with app.app_context():
        uid = _uid("self_user")
    r = client.post(f"/users/{uid}/report", data={"reason": "x"})
    assert r.status_code == 400
    with app.app_context():
        assert Report.query.count() == 0


def test_duplicate_user_report_rejected(app, client):
    with app.app_context():
        tid = auth_service.register_user("dur_target", "password123").id
    _auth(client, "dur_reporter")
    assert client.post(f"/users/{tid}/report", data={"reason": "1"}).status_code == 302
    assert client.post(f"/users/{tid}/report", data={"reason": "2"}).status_code == 400
    with app.app_context():
        assert Report.query.filter_by(reported_user_id=tid).count() == 1


def test_report_unknown_or_dormant_user_404(app, client):
    with app.app_context():
        dormant = auth_service.register_user("dormant_target", "password123")
        dormant.status = "dormant"
        db.session.commit()
        did = dormant.id
    _auth(client, "ru_seeker")
    assert client.post(f"/users/{did}/report", data={"reason": "x"}).status_code == 404
    assert client.post("/users/unknown-id/report", data={"reason": "x"}).status_code == 404
    with app.app_context():
        assert Report.query.count() == 0


def test_threshold_auto_dormant_user(app, client):
    with app.app_context():
        tid = auth_service.register_user("victim_u", "password123").id
    for i in range(3):
        _auth(client, f"ur{i}")
        client.post(f"/users/{tid}/report", data={"reason": f"s{i}"})
    with app.app_context():
        assert db.session.get(User, tid).status == "dormant"
        assert (
            Report.query.filter_by(reported_user_id=tid, status="auto_actioned").count()
            == 3
        )
        audit = AuditLog.query.filter_by(
            action="user_auto_dormant",
            target=tid,
        ).one()
        assert audit.actor_type == "system"
        assert audit.actor_id is None
    # 휴면 사용자는 로그인해도 인증 세션이 유지되지 않는다
    _logout(client)
    client.post("/login", data={"username": "victim_u", "password": "password123"})
    assert client.get("/me", follow_redirects=False).status_code in (302, 401)


def test_dormant_user_products_hidden(app, client):
    with app.app_context():
        seller = auth_service.register_user("dhp_seller", "password123")
        db.session.add(
            Product(title="휴면판매상품", description="d", price=100, seller_id=seller.id)
        )
        db.session.commit()
        tid = seller.id
    for i in range(3):
        _auth(client, f"dhp_rep{i}")
        client.post(f"/users/{tid}/report", data={"reason": f"s{i}"})
    with app.app_context():
        assert db.session.get(User, tid).status == "dormant"
    assert "휴면판매상품" not in client.get("/products").get_data(as_text=True)


def test_report_user_requires_csrf(app, client):
    with app.app_context():
        tid = auth_service.register_user("csu_target", "password123").id
    _auth(client, "csu_rep")
    app.config["WTF_CSRF_ENABLED"] = True
    r = client.post(f"/users/{tid}/report", data={"reason": "x"})
    assert r.status_code == 400
    with app.app_context():
        assert Report.query.count() == 0


def test_admin_account_cannot_be_reported_or_auto_dormant(app, client):
    with app.app_context():
        admin = User(
            username="protected_admin",
            password_hash=auth_service.hash_password("password123"),
            role="admin",
        )
        db.session.add(admin)
        db.session.commit()
        admin_id = admin.id

    _auth(client, "admin_reporter")
    profile = client.get(f"/users/{admin_id}")
    assert profile.status_code == 200
    assert "이 사용자 신고" not in profile.get_data(as_text=True)
    assert (
        client.post(
            f"/users/{admin_id}/report",
            data={"reason": "관리자 무력화 시도"},
        ).status_code
        == 404
    )
    with app.app_context():
        assert db.session.get(User, admin_id).status == "active"
        assert Report.query.count() == 0


def test_dormant_reporter_is_rejected_at_service_boundary(app):
    with app.app_context():
        seller = auth_service.register_user("boundary_seller", "password123")
        reporter = auth_service.register_user(
            "boundary_reporter", "password123"
        )
        reporter.status = "dormant"
        product = Product(
            title="경계 상품",
            description="d",
            price=100,
            seller_id=seller.id,
        )
        db.session.add(product)
        db.session.commit()

        with pytest.raises(auth_service.ValidationError):
            report_service.report_product(
                reporter,
                product.id,
                "휴면 계정의 서비스 직접 호출",
            )
        assert Report.query.count() == 0


def test_report_transaction_rolls_back_on_commit_failure(
    app, monkeypatch
):
    with app.app_context():
        seller = auth_service.register_user("tx_seller", "password123")
        reporter = auth_service.register_user("tx_reporter", "password123")
        product = Product(
            title="트랜잭션 상품",
            description="d",
            price=100,
            seller_id=seller.id,
        )
        db.session.add(product)
        db.session.commit()
        product_id = product.id

        def fail_commit():
            raise RuntimeError("forced commit failure")

        monkeypatch.setattr(db.session, "commit", fail_commit)
        with pytest.raises(RuntimeError):
            report_service.report_product(
                reporter,
                product_id,
                "롤백 검증",
            )
        assert Report.query.count() == 0
        assert AuditLog.query.filter_by(action="report_product").count() == 0
        assert db.session.get(Product, product_id).status == "active"


@pytest.mark.parametrize("reason", ["   ", "x" * 1001])
def test_report_reason_database_constraint(app, reason):
    with app.app_context():
        target = auth_service.register_user("db_reason_target", "password123")
        reporter = auth_service.register_user(
            "db_reason_reporter", "password123"
        )
        db.session.add(
            Report(
                reporter_id=reporter.id,
                reported_user_id=target.id,
                reason=reason,
            )
        )
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


def test_report_rate_limit_is_shared_across_target_types(monkeypatch):
    monkeypatch.setattr(TestConfig, "RATELIMIT_ENABLED", True)
    monkeypatch.setattr(TestConfig, "REPORT_USER_RATE_LIMIT", "2 per hour")
    monkeypatch.setattr(TestConfig, "REPORT_IP_RATE_LIMIT", "100 per hour")
    rate_app = create_app("test")
    rate_client = rate_app.test_client()
    try:
        with rate_app.app_context():
            db.create_all()
            seller = auth_service.register_user("rate_seller", "password123")
            target = auth_service.register_user("rate_target", "password123")
            products = [
                Product(
                    title=f"제한 상품 {index}",
                    description="d",
                    price=100,
                    seller_id=seller.id,
                )
                for index in range(2)
            ]
            db.session.add_all(products)
            db.session.commit()
            target_id = target.id
            product_ids = [product.id for product in products]
        _auth(rate_client, "rate_reporter")
        assert rate_client.post(
            f"/products/{product_ids[0]}/report",
            data={"reason": "첫 요청"},
        ).status_code == 302
        assert rate_client.post(
            f"/users/{target_id}/report",
            data={"reason": "둘째 요청"},
        ).status_code == 302
        assert rate_client.post(
            f"/products/{product_ids[1]}/report",
            data={"reason": "셋째 요청"},
        ).status_code == 429
    finally:
        with rate_app.app_context():
            db.session.remove()
            db.drop_all()
        limiter.reset()
        limiter.enabled = False


def test_report_ip_rate_limit_spans_multiple_accounts(monkeypatch):
    monkeypatch.setattr(TestConfig, "RATELIMIT_ENABLED", True)
    monkeypatch.setattr(TestConfig, "REPORT_USER_RATE_LIMIT", "100 per hour")
    monkeypatch.setattr(TestConfig, "REPORT_IP_RATE_LIMIT", "3 per hour")
    rate_app = create_app("test")
    rate_client = rate_app.test_client()
    try:
        with rate_app.app_context():
            db.create_all()
            seller = auth_service.register_user(
                "ip_rate_seller", "password123"
            )
            products = [
                Product(
                    title=f"IP 제한 상품 {index}",
                    description="d",
                    price=100,
                    seller_id=seller.id,
                )
                for index in range(4)
            ]
            db.session.add_all(products)
            db.session.commit()
            product_ids = [product.id for product in products]

        statuses = []
        for index, product_id in enumerate(product_ids):
            _auth(rate_client, f"ip_rate_reporter{index}")
            response = rate_client.post(
                f"/products/{product_id}/report",
                data={"reason": f"신고 {index}"},
            )
            statuses.append(response.status_code)
        assert statuses == [302, 302, 302, 429]
    finally:
        with rate_app.app_context():
            db.session.remove()
            db.drop_all()
        limiter.reset()
        limiter.enabled = False
