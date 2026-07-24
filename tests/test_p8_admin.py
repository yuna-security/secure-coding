"""P8 관리자 테스트 (R7).

체크리스트/설계 매핑:
- AC7.1 RBAC(비로그인 redirect / 비관리자 403 / 관리자 200)
- AC7.2 사용자 휴면/복구  - AC7.3 상품 차단/복구/삭제
- AC7.4 신고 검토(pending→reviewed)·결정(resolved, upheld/reversed/dismissed)
- AC7.5 거래·감사 로그 열람, 민감정보(해시·잔액) 비노출, 잔액 직접수정 없음
- 트랜잭션 경합 방어: 조건부 UPDATE 영향행수!=1 → 409
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
import uuid

import pytest
from werkzeug.exceptions import Forbidden

from app import create_app
from app.admin import service as admin_service
from app.auth import service as auth_service
from app.config import TestConfig
from app.extensions import db
from app.models import AuditLog, Product, Report, User


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


def _make_admin(app, name="admin"):
    with app.app_context():
        admin = auth_service.register_user(name, "password123")
        admin.role = "admin"
        db.session.commit()
        return admin.id


def _login_admin(app, client, name="admin"):
    aid = _make_admin(app, name)
    _logout(client)
    _login(client, name)
    return aid


def _make_user(app, name, status="active"):
    with app.app_context():
        u = auth_service.register_user(name, "password123")
        if status != "active":
            u.status = status
            db.session.commit()
        return u.id


def _make_product(app, seller_name, title="상품", status="active"):
    with app.app_context():
        seller = auth_service.register_user(seller_name, "password123")
        p = Product(
            title=title, description="d", price=100,
            seller_id=seller.id, status=status,
        )
        db.session.add(p)
        db.session.commit()
        return p.id


def _auto_actioned_product(app, title="자동차단상품"):
    key = uuid.uuid4().hex[:8]
    with app.app_context():
        seller = auth_service.register_user(f"aps_{key}", "password123")
        reporter = auth_service.register_user(f"apr_{key}", "password123")
        p = Product(
            title=title, description="d", price=100,
            seller_id=seller.id, status="blocked",
        )
        db.session.add(p)
        db.session.flush()
        rep = Report(
            reporter_id=reporter.id, reported_product_id=p.id,
            reason="사유", status="auto_actioned",
        )
        db.session.add(rep)
        db.session.commit()
        return p.id, rep.id


def _auto_actioned_user(app, name="자동휴면유저"):
    key = uuid.uuid4().hex[:8]
    with app.app_context():
        target = auth_service.register_user(f"aut_{key}", "password123")
        target.status = "dormant"
        reporter = auth_service.register_user(f"aur_{key}", "password123")
        db.session.flush()
        rep = Report(
            reporter_id=reporter.id, reported_user_id=target.id,
            reason="사유", status="auto_actioned",
        )
        db.session.add(rep)
        db.session.commit()
        return target.id, rep.id


def _auto_actioned_product_cohort(app, count=3):
    key = uuid.uuid4().hex[:8]
    with app.app_context():
        seller = auth_service.register_user(f"co_s_{key}", "password123")
        product = Product(
            title="자동조치 묶음",
            description="d",
            price=100,
            seller_id=seller.id,
            status="blocked",
        )
        db.session.add(product)
        db.session.flush()
        reports = []
        for index in range(count):
            reporter = auth_service.register_user(
                f"co_r{index}_{key}",
                "password123",
            )
            reports.append(
                Report(
                    reporter_id=reporter.id,
                    reported_product_id=product.id,
                    reason=f"사유 {index}",
                    status="auto_actioned",
                )
            )
        db.session.add_all(reports)
        db.session.commit()
        return product.id, [report.id for report in reports]


def _pending_report_on_user(app):
    with app.app_context():
        target = auth_service.register_user("pr_target", "password123")
        reporter = auth_service.register_user("pr_reporter", "password123")
        db.session.flush()
        rep = Report(
            reporter_id=reporter.id, reported_user_id=target.id,
            reason="사유", status="pending",
        )
        db.session.add(rep)
        db.session.commit()
        return target.id, rep.id


GET_ROUTES = [
    "/admin",
    "/admin/users",
    "/admin/products",
    "/admin/reports",
    "/admin/logs",
    "/admin/transactions",
]


# ---------- RBAC (AC7.1) ----------

@pytest.mark.parametrize("path", GET_ROUTES)
def test_admin_get_requires_login(app, client, path):
    r = client.get(path, follow_redirects=False)
    assert r.status_code in (302, 401)


@pytest.mark.parametrize("path", GET_ROUTES)
def test_admin_get_forbidden_for_normal_user(app, client, path):
    _auth(client, "plain_user")
    assert client.get(path).status_code == 403


@pytest.mark.parametrize("path", GET_ROUTES)
def test_admin_get_ok_for_admin(app, client, path):
    _login_admin(app, client)
    assert client.get(path).status_code == 200


def test_admin_post_forbidden_for_normal_user(app, client):
    uid = _make_user(app, "victim")
    _auth(client, "attacker")
    assert client.post(f"/admin/users/{uid}/dormant").status_code == 403
    with app.app_context():
        assert db.session.get(User, uid).status == "active"


def test_admin_post_requires_login(app, client):
    uid = _make_user(app, "victim2")
    r = client.post(f"/admin/users/{uid}/dormant", follow_redirects=False)
    assert r.status_code in (302, 401)


def test_admin_service_rechecks_actor_role(app):
    actor_id = _make_user(app, "forged_admin_actor")
    target_id = _make_user(app, "service_target")
    with app.app_context():
        actor = db.session.get(User, actor_id)
        with pytest.raises(Forbidden):
            admin_service.set_user_dormant(actor, target_id)
        assert db.session.get(User, target_id).status == "active"
        assert AuditLog.query.filter_by(actor_type="admin").count() == 0


# ---------- 사용자 상태 (AC7.2) ----------

def test_user_dormant_and_restore(app, client):
    uid = _make_user(app, "target_u")
    _login_admin(app, client)
    assert client.post(f"/admin/users/{uid}/dormant").status_code == 302
    with app.app_context():
        assert db.session.get(User, uid).status == "dormant"
        assert AuditLog.query.filter_by(
            actor_type="admin", action="admin_user_dormant", target=uid
        ).count() == 1
    assert client.post(f"/admin/users/{uid}/restore").status_code == 302
    with app.app_context():
        assert db.session.get(User, uid).status == "active"
        assert AuditLog.query.filter_by(
            actor_type="admin", action="admin_user_restore", target=uid
        ).count() == 1


def test_cannot_dormant_admin(app, client):
    other_admin = _make_admin(app, "other_admin")
    _login_admin(app, client, "acting_admin")
    assert client.post(f"/admin/users/{other_admin}/dormant").status_code == 400
    with app.app_context():
        u = db.session.get(User, other_admin)
        assert u.status == "active" and u.role == "admin"
        assert AuditLog.query.filter_by(action="admin_user_dormant").count() == 0


def test_dormant_already_dormant_conflicts(app, client):
    uid = _make_user(app, "dorm_u", status="dormant")
    _login_admin(app, client)
    assert client.post(f"/admin/users/{uid}/dormant").status_code == 409


def test_restore_active_user_conflicts(app, client):
    uid = _make_user(app, "act_u")
    _login_admin(app, client)
    assert client.post(f"/admin/users/{uid}/restore").status_code == 409


def test_auto_dormant_user_requires_report_resolution_to_restore(app, client):
    uid, _ = _auto_actioned_user(app)
    _login_admin(app, client)
    assert client.post(f"/admin/users/{uid}/restore").status_code == 409
    with app.app_context():
        assert db.session.get(User, uid).status == "dormant"


def test_dormant_unknown_user_404(app, client):
    _login_admin(app, client)
    assert client.post("/admin/users/nope/dormant").status_code == 404


# ---------- 상품 상태 (AC7.3) ----------

def test_product_block_restore_delete(app, client):
    pid = _make_product(app, "ps1", title="상품관리대상")
    _login_admin(app, client)
    assert client.post(f"/admin/products/{pid}/block").status_code == 302
    with app.app_context():
        assert db.session.get(Product, pid).status == "blocked"
    assert client.post(f"/admin/products/{pid}/restore").status_code == 302
    with app.app_context():
        assert db.session.get(Product, pid).status == "active"
    assert client.post(f"/admin/products/{pid}/delete").status_code == 302
    with app.app_context():
        assert db.session.get(Product, pid).status == "deleted"
    # soft delete 복구
    assert client.post(f"/admin/products/{pid}/restore").status_code == 302
    with app.app_context():
        assert db.session.get(Product, pid).status == "active"
        for action in ("admin_product_block", "admin_product_delete"):
            assert AuditLog.query.filter_by(
                actor_type="admin", action=action, target=pid
            ).count() == 1


def test_block_already_blocked_conflicts(app, client):
    pid = _make_product(app, "ps2", status="blocked")
    _login_admin(app, client)
    assert client.post(f"/admin/products/{pid}/block").status_code == 409


def test_delete_already_deleted_conflicts(app, client):
    pid = _make_product(app, "ps3", status="deleted")
    _login_admin(app, client)
    assert client.post(f"/admin/products/{pid}/delete").status_code == 409


def test_auto_blocked_product_requires_report_resolution_to_restore(app, client):
    pid, _ = _auto_actioned_product(app, title="복구 우회 차단")
    _login_admin(app, client)
    assert client.post(f"/admin/products/{pid}/restore").status_code == 409
    with app.app_context():
        assert db.session.get(Product, pid).status == "blocked"


def test_admin_can_audit_deleted_product_but_normal_user_cannot(app, client):
    pid = _make_product(
        app,
        "deleted_seller",
        title="삭제 감사 대상",
        status="deleted",
    )
    _auth(client, "deleted_viewer")
    assert client.get(f"/products/{pid}").status_code == 404
    _login_admin(app, client)
    response = client.get(f"/products/{pid}")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "삭제 감사 대상" in body
    assert "이 상품 신고" not in body


# ---------- 신고 검토 (AC7.4) ----------

def test_report_review_pending(app, client):
    _, rid = _pending_report_on_user(app)
    _login_admin(app, client)
    assert client.post(f"/admin/reports/{rid}/review").status_code == 302
    with app.app_context():
        rep = db.session.get(Report, rid)
        assert rep.status == "reviewed" and rep.reviewed_by is not None
        assert rep.reviewed_at is not None and rep.resolution is None
        assert AuditLog.query.filter_by(
            actor_type="admin", action="admin_report_review", target=rid
        ).count() == 1


def test_review_non_pending_conflicts(app, client):
    _, rid = _auto_actioned_product(app, title="검토경합")
    _login_admin(app, client)
    # auto_actioned는 review 대상이 아님 → 409
    assert client.post(f"/admin/reports/{rid}/review").status_code == 409


def test_double_review_conflicts(app, client):
    _, rid = _pending_report_on_user(app)
    _login_admin(app, client)
    assert client.post(f"/admin/reports/{rid}/review").status_code == 302
    assert client.post(f"/admin/reports/{rid}/review").status_code == 409


def test_resolve_reviewed_dismissed(app, client):
    _, rid = _pending_report_on_user(app)
    _login_admin(app, client)
    client.post(f"/admin/reports/{rid}/review")
    r = client.post(f"/admin/reports/{rid}/resolve", data={"resolution": "dismissed"})
    assert r.status_code == 302
    with app.app_context():
        rep = db.session.get(Report, rid)
        assert rep.status == "resolved" and rep.resolution == "dismissed"
        assert AuditLog.query.filter_by(
            actor_type="admin", action="admin_report_resolve", target=rid
        ).count() == 1


def test_resolve_auto_actioned_upheld_keeps_block(app, client):
    pid, rid = _auto_actioned_product(app, title="유지대상")
    _login_admin(app, client)
    r = client.post(f"/admin/reports/{rid}/resolve", data={"resolution": "upheld"})
    assert r.status_code == 302
    with app.app_context():
        assert db.session.get(Product, pid).status == "blocked"
        rep = db.session.get(Report, rid)
        assert rep.status == "resolved" and rep.resolution == "upheld"


def test_resolve_auto_actioned_reversed_restores_product(app, client):
    pid, rid = _auto_actioned_product(app, title="복구대상")
    _login_admin(app, client)
    r = client.post(f"/admin/reports/{rid}/resolve", data={"resolution": "reversed"})
    assert r.status_code == 302
    with app.app_context():
        assert db.session.get(Product, pid).status == "active"
        rep = db.session.get(Report, rid)
        assert rep.status == "resolved" and rep.resolution == "reversed"
        assert AuditLog.query.filter_by(
            actor_type="admin", action="admin_product_restore", target=pid
        ).count() == 1


def test_resolve_auto_actioned_reversed_restores_user(app, client):
    uid, rid = _auto_actioned_user(app)
    _login_admin(app, client)
    r = client.post(f"/admin/reports/{rid}/resolve", data={"resolution": "reversed"})
    assert r.status_code == 302
    with app.app_context():
        assert db.session.get(User, uid).status == "active"
        assert AuditLog.query.filter_by(
            actor_type="admin", action="admin_user_restore", target=uid
        ).count() == 1


@pytest.mark.parametrize(
    ("resolution", "expected_status"),
    [("upheld", "blocked"), ("reversed", "active")],
)
def test_auto_actioned_cohort_is_resolved_consistently(
    app, client, resolution, expected_status
):
    pid, report_ids = _auto_actioned_product_cohort(app)
    admin_id = _login_admin(app, client)
    response = client.post(
        f"/admin/reports/{report_ids[0]}/resolve",
        data={"resolution": resolution},
    )
    assert response.status_code == 302
    with app.app_context():
        reports = Report.query.filter(
            Report.id.in_(report_ids)
        ).all()
        assert len(reports) == 3
        assert {
            (report.status, report.resolution, report.reviewed_by)
            for report in reports
        } == {("resolved", resolution, admin_id)}
        assert db.session.get(Product, pid).status == expected_status
        audit = AuditLog.query.filter_by(
            action="admin_report_resolve",
            target=report_ids[0],
        ).one()
        assert "cohort=3" in audit.detail

    # 같은 자동조치 묶음의 다른 신고에 상반된 결정을 내릴 수 없다.
    opposite = "reversed" if resolution == "upheld" else "upheld"
    assert client.post(
        f"/admin/reports/{report_ids[1]}/resolve",
        data={"resolution": opposite},
    ).status_code == 409


def test_reversed_report_does_not_resurrect_later_deleted_product(app, client):
    pid, report_ids = _auto_actioned_product_cohort(app)
    with app.app_context():
        db.session.get(Product, pid).status = "deleted"
        db.session.commit()
    _login_admin(app, client)
    assert client.post(
        f"/admin/reports/{report_ids[0]}/resolve",
        data={"resolution": "reversed"},
    ).status_code == 302
    with app.app_context():
        assert db.session.get(Product, pid).status == "deleted"
        assert Report.query.filter(
            Report.id.in_(report_ids),
            Report.status == "resolved",
            Report.resolution == "reversed",
        ).count() == 3
        assert AuditLog.query.filter_by(
            action="admin_product_restore",
            target=pid,
        ).count() == 0


def test_resolve_wrong_resolution_for_status_400(app, client):
    # auto_actioned에 dismissed 불가
    _, rid_auto = _auto_actioned_product(app, title="잘못된결정")
    _login_admin(app, client)
    assert client.post(
        f"/admin/reports/{rid_auto}/resolve", data={"resolution": "dismissed"}
    ).status_code == 400
    # reviewed에 reversed 불가
    _, rid_rev = _pending_report_on_user(app)
    client.post(f"/admin/reports/{rid_rev}/review")
    assert client.post(
        f"/admin/reports/{rid_rev}/resolve", data={"resolution": "reversed"}
    ).status_code == 400
    with app.app_context():
        assert db.session.get(Report, rid_auto).status == "auto_actioned"
        assert db.session.get(Report, rid_rev).status == "reviewed"


def test_resolve_pending_conflicts(app, client):
    _, rid = _pending_report_on_user(app)
    _login_admin(app, client)
    # 검토 전 pending은 곧바로 결정 불가 → 409
    assert client.post(
        f"/admin/reports/{rid}/resolve", data={"resolution": "upheld"}
    ).status_code == 409


def test_resolve_invalid_value_400(app, client):
    _, rid = _auto_actioned_product(app, title="유효성")
    _login_admin(app, client)
    assert client.post(
        f"/admin/reports/{rid}/resolve", data={"resolution": "bogus"}
    ).status_code == 400


def test_admin_action_rolls_back_if_audit_write_fails(app, monkeypatch):
    uid = _make_user(app, "audit_fail_target")
    admin_id = _make_admin(app, "audit_fail_admin")
    with app.app_context():
        admin = db.session.get(User, admin_id)

        def fail_audit(*args, **kwargs):
            raise RuntimeError("forced audit failure")

        monkeypatch.setattr(admin_service, "write_audit", fail_audit)
        with pytest.raises(RuntimeError):
            admin_service.set_user_dormant(admin, uid)
        assert db.session.get(User, uid).status == "active"
        assert AuditLog.query.filter_by(
            action="admin_user_dormant",
            target=uid,
        ).count() == 0


def test_report_resolution_rolls_back_if_restore_fails(app, monkeypatch):
    pid, report_ids = _auto_actioned_product_cohort(app)
    admin_id = _make_admin(app, "restore_fail_admin")
    with app.app_context():
        admin = db.session.get(User, admin_id)

        def fail_restore(*args, **kwargs):
            raise RuntimeError("forced restore failure")

        monkeypatch.setattr(
            admin_service,
            "_restore_report_target",
            fail_restore,
        )
        with pytest.raises(RuntimeError):
            admin_service.resolve_report(
                admin,
                report_ids[0],
                "reversed",
            )
        assert db.session.get(Product, pid).status == "blocked"
        assert Report.query.filter(
            Report.id.in_(report_ids),
            Report.status == "auto_actioned",
        ).count() == 3
        assert AuditLog.query.filter_by(
            action="admin_report_resolve",
        ).count() == 0


# ---------- 열람·민감정보 (AC7.5) ----------

def test_users_list_hides_password_hash(app, client):
    uid = _make_user(app, "secret_u")
    with app.app_context():
        user = db.session.get(User, uid)
        user.balance = 987_654_321
        db.session.commit()
        pw_hash = user.password_hash
    _login_admin(app, client)
    body = client.get("/admin/users").get_data(as_text=True)
    assert "secret_u" in body
    assert pw_hash not in body
    assert "password_hash" not in body
    assert "987654321" not in body
    assert "987,654,321" not in body


def test_audit_log_detail_is_html_escaped(app, client):
    _login_admin(app, client)
    with app.app_context():
        db.session.add(
            AuditLog(
                actor_type="system",
                action="xss_probe",
                target="<img src=x onerror=alert(1)>",
                detail="<script>alert(2)</script>",
            )
        )
        db.session.commit()
    body = client.get("/admin/logs").get_data(as_text=True)
    assert "<script>alert(2)</script>" not in body
    assert "<img src=x onerror=alert(1)>" not in body
    assert "&lt;script&gt;" in body


def test_logs_view_shows_admin_actions(app, client):
    uid = _make_user(app, "logged_u")
    _login_admin(app, client)
    client.post(f"/admin/users/{uid}/dormant")
    body = client.get("/admin/logs").get_data(as_text=True)
    assert "admin_user_dormant" in body


def test_transactions_view_empty_ok(app, client):
    _login_admin(app, client)
    r = client.get("/admin/transactions")
    assert r.status_code == 200
    assert "거래 기록이 없습니다." in r.get_data(as_text=True)


# ---------- CSRF (②) ----------

def test_admin_action_requires_csrf(app, client):
    uid = _make_user(app, "csrf_u")
    _login_admin(app, client)
    app.config["WTF_CSRF_ENABLED"] = True
    r = client.post(f"/admin/users/{uid}/dormant")
    assert r.status_code == 400
    with app.app_context():
        assert db.session.get(User, uid).status == "active"


def test_concurrent_report_resolution_has_one_consistent_winner(monkeypatch):
    filename = f"p8-race-{uuid.uuid4().hex}.db"
    monkeypatch.setattr(
        TestConfig,
        "SQLALCHEMY_DATABASE_URI",
        f"sqlite:///{filename}",
    )
    monkeypatch.setattr(
        TestConfig,
        "SQLALCHEMY_ENGINE_OPTIONS",
        {
            "connect_args": {
                "check_same_thread": False,
                "timeout": 10,
            }
        },
    )
    race_app = create_app("test")
    db_path = Path(race_app.instance_path) / filename
    try:
        with race_app.app_context():
            db.create_all()
            admins = [
                auth_service.register_user(
                    f"race_admin_{index}",
                    "password123",
                )
                for index in range(2)
            ]
            for admin in admins:
                admin.role = "admin"
            seller = auth_service.register_user("race_seller", "password123")
            reporter = auth_service.register_user(
                "race_reporter",
                "password123",
            )
            product = Product(
                title="경합 상품",
                description="d",
                price=100,
                seller_id=seller.id,
                status="blocked",
            )
            db.session.add(product)
            db.session.flush()
            report = Report(
                reporter_id=reporter.id,
                reported_product_id=product.id,
                reason="경합 신고",
                status="auto_actioned",
            )
            db.session.add(report)
            db.session.commit()
            product_id, report_id = product.id, report.id

        start = Barrier(2)

        def resolve(username, resolution):
            thread_client = race_app.test_client()
            assert _login(thread_client, username).status_code == 302
            start.wait(timeout=10)
            return (
                resolution,
                thread_client.post(
                    f"/admin/reports/{report_id}/resolve",
                    data={"resolution": resolution},
                ).status_code,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(
                    lambda args: resolve(*args),
                    [
                        ("race_admin_0", "upheld"),
                        ("race_admin_1", "reversed"),
                    ],
                )
            )

        assert sorted(status for _, status in results) == [302, 409]
        winner = next(
            resolution for resolution, status in results if status == 302
        )
        with race_app.app_context():
            persisted = db.session.get(Report, report_id)
            assert persisted.status == "resolved"
            assert persisted.resolution == winner
            expected_product_status = (
                "active" if winner == "reversed" else "blocked"
            )
            assert db.session.get(Product, product_id).status == expected_product_status
            assert AuditLog.query.filter_by(
                action="admin_report_resolve",
                target=report_id,
            ).count() == 1
    finally:
        with race_app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()
        if db_path.exists():
            db_path.unlink()
