"""P7 송금·지갑 테스트 (R5).

체크리스트/설계 매핑:
- AC5.1 grant 원장 지급(관리자)  - AC5.2 양의정수·잔액이내·자기송금금지
- AC5.3 원자적 조건부 차감 + 불변 원장  - AC5.4 멱등·409  - AC5.5 본인 내역만
- SR-03 송금 트랜잭션 무결성  - balance 불변식(원장 합계와 일치)
"""
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import Conflict

from app import create_app
from app.admin import service as admin_service
from app.auth import service as auth_service
from app.config import TestConfig
from app.extensions import db
from app.wallet import service as wallet_service
from app.models import Transfer, User, AuditLog


# ---------- 헬퍼 ----------

def _login(client, username, password="password123"):
    return client.post("/login", data={"username": username, "password": password})


def _logout(client):
    client.post("/logout")


def _auth(client, username):
    _logout(client)
    client.post("/register", data={"username": username, "password": "password123"})
    _login(client, username)


def _uid(username):
    return User.query.filter_by(username=username).one().id


def _make_user(app, name, balance=0, status="active", role="user"):
    with app.app_context():
        u = auth_service.register_user(name, "password123")
        u.status = status
        u.role = role
        if balance:
            u.balance = balance
            db.session.add(Transfer(
                kind="grant",
                sender_id=None,
                receiver_id=u.id,
                amount=balance,
                memo="test seed",
                idempotency_key=f"seed-{uuid.uuid4().hex}",
            ))
        db.session.commit()
        return u.id


def _balance(app, username):
    with app.app_context():
        return User.query.filter_by(username=username).one().balance


def _key():
    return uuid.uuid4().hex  # 32자, 멱등 키 범위(16~64) 내


# ---------- 서비스: 송금 무결성 ----------

def test_transfer_moves_points_and_records_ledger(app):
    _make_user(app, "s_send", balance=1000)
    _make_user(app, "s_recv", balance=0)
    with app.app_context():
        sender = User.query.filter_by(username="s_send").one()
        wallet_service.transfer_points(sender, "s_recv", "300", "고마워요", _key())
    assert _balance(app, "s_send") == 700
    assert _balance(app, "s_recv") == 300
    with app.app_context():
        t = Transfer.query.filter_by(kind="transfer").one()
        assert t.amount == 300 and t.memo == "고마워요"
        assert t.sender_id == _uid("s_send") and t.receiver_id == _uid("s_recv")
        assert AuditLog.query.filter_by(action="transfer").count() == 1
        # 불변식: 원장 재계산 == materialized balance
        assert wallet_service.ledger_balance(_uid("s_send")) == 700
        assert wallet_service.ledger_balance(_uid("s_recv")) == 300


def test_insufficient_balance_rejected(app):
    _make_user(app, "ins_s", balance=100)
    _make_user(app, "ins_r", balance=0)
    with app.app_context():
        sender = User.query.filter_by(username="ins_s").one()
        with pytest.raises(auth_service.ValidationError):
            wallet_service.transfer_points(sender, "ins_r", "101", "", _key())
    assert _balance(app, "ins_s") == 100
    assert _balance(app, "ins_r") == 0
    with app.app_context():
        assert Transfer.query.filter_by(kind="transfer").count() == 0


def test_self_transfer_rejected(app):
    _make_user(app, "self_s", balance=500)
    with app.app_context():
        sender = User.query.filter_by(username="self_s").one()
        with pytest.raises(auth_service.ValidationError):
            wallet_service.transfer_points(sender, "self_s", "10", "", _key())
        assert Transfer.query.filter_by(kind="transfer").count() == 0


@pytest.mark.parametrize("bad", ["0", "-5", "abc", "1.5", "", "1000000001"])
def test_invalid_amount_rejected(app, bad):
    _make_user(app, "amt_s", balance=1_000_000_000)
    _make_user(app, "amt_r", balance=0)
    with app.app_context():
        sender = User.query.filter_by(username="amt_s").one()
        with pytest.raises(auth_service.ValidationError):
            wallet_service.transfer_points(sender, "amt_r", bad, "", _key())
        assert Transfer.query.filter_by(kind="transfer").count() == 0


def test_unknown_or_dormant_recipient_rejected(app):
    _make_user(app, "ur_s", balance=500)
    _make_user(app, "ur_dormant", balance=0, status="dormant")
    with app.app_context():
        sender = User.query.filter_by(username="ur_s").one()
        with pytest.raises(auth_service.ValidationError):
            wallet_service.transfer_points(sender, "ur_dormant", "10", "", _key())
        with pytest.raises(auth_service.ValidationError):
            wallet_service.transfer_points(sender, "nobody", "10", "", _key())
        assert Transfer.query.filter_by(kind="transfer").count() == 0


def test_dormant_sender_rejected(app):
    _make_user(app, "ds_s", balance=500, status="dormant")
    _make_user(app, "ds_r", balance=0)
    with app.app_context():
        sender = User.query.filter_by(username="ds_s").one()
        with pytest.raises(auth_service.ValidationError):
            wallet_service.transfer_points(sender, "ds_r", "10", "", _key())
        assert Transfer.query.filter_by(kind="transfer").count() == 0


# ---------- 멱등 (AC5.4) ----------

def test_idempotent_replay_same_key_same_params(app):
    _make_user(app, "idem_s", balance=1000)
    _make_user(app, "idem_r", balance=0)
    key = _key()
    with app.app_context():
        sender = User.query.filter_by(username="idem_s").one()
        first = wallet_service.transfer_points(sender, "idem_r", "200", "m", key)
        first_id = first.id
        second = wallet_service.transfer_points(sender, "idem_r", "200", "m", key)
        assert second.id == first_id  # 동일 결과 재응답
    # 한 번만 반영
    assert _balance(app, "idem_s") == 800
    assert _balance(app, "idem_r") == 200
    with app.app_context():
        assert Transfer.query.filter_by(kind="transfer").count() == 1


def test_idempotency_conflict_same_key_different_params(app):
    _make_user(app, "conf_s", balance=1000)
    _make_user(app, "conf_r", balance=0)
    _make_user(app, "conf_r2", balance=0)
    key = _key()
    with app.app_context():
        sender = User.query.filter_by(username="conf_s").one()
        wallet_service.transfer_points(sender, "conf_r", "200", "m", key)
        # 같은 키, 다른 금액 → 409
        with pytest.raises(Conflict):
            wallet_service.transfer_points(sender, "conf_r", "300", "m", key)
        # 같은 키, 다른 수신자 → 409
        with pytest.raises(Conflict):
            wallet_service.transfer_points(sender, "conf_r2", "200", "m", key)
    assert _balance(app, "conf_s") == 800  # 최초 1건만 반영
    with app.app_context():
        assert Transfer.query.filter_by(kind="transfer").count() == 1


def test_idempotent_replay_survives_recipient_dormancy(app):
    _make_user(app, "late_s", balance=100)
    recipient_id = _make_user(app, "late_r")
    key = _key()
    with app.app_context():
        sender = User.query.filter_by(username="late_s").one()
        first = wallet_service.transfer_points(
            sender, "late_r", "10", "once", key
        )
        db.session.get(User, recipient_id).status = "dormant"
        db.session.commit()
        replay = wallet_service.transfer_points(
            sender, "late_r", "10", "once", key
        )
        assert replay.id == first.id
        assert Transfer.query.filter_by(kind="transfer").count() == 1


@pytest.mark.parametrize(
    ("recipient", "memo", "key"),
    [
        (["victim"], "", "x" * 32),
        ("shape_r", ["memo"], "x" * 32),
        ("shape_r", "", ["key"]),
    ],
)
def test_malformed_input_shapes_return_validation_error(
    app, recipient, memo, key
):
    _make_user(app, "shape_s", balance=100)
    _make_user(app, "shape_r")
    with app.app_context():
        sender = User.query.filter_by(username="shape_s").one()
        with pytest.raises(auth_service.ValidationError):
            wallet_service.transfer_points(sender, recipient, "10", memo, key)


@pytest.mark.parametrize("bad", ["short", "", "x" * 65])
def test_invalid_idempotency_key_rejected(app, bad):
    _make_user(app, "ik_s", balance=500)
    _make_user(app, "ik_r", balance=0)
    with app.app_context():
        sender = User.query.filter_by(username="ik_s").one()
        with pytest.raises(auth_service.ValidationError):
            wallet_service.transfer_points(sender, "ik_r", "10", "", bad)
        assert Transfer.query.filter_by(kind="transfer").count() == 0


# ---------- HTTP 라우트 ----------

def test_wallet_requires_login(app, client):
    assert client.get("/wallet", follow_redirects=False).status_code in (302, 401)
    assert client.post("/wallet/transfer", follow_redirects=False).status_code in (302, 401)


def test_admin_cannot_use_user_wallet(app, client):
    _make_user(app, "wallet_admin", role="admin")
    _login(client, "wallet_admin")
    assert client.get("/wallet").status_code == 403
    assert client.post(
        "/wallet/transfer",
        data={
            "recipient": "anyone",
            "amount": "1",
            "idempotency_key": _key(),
        },
    ).status_code == 403


def test_wallet_page_shows_only_own_history(app, client):
    _make_user(app, "own_a", balance=500)
    _make_user(app, "own_b", balance=500)
    _make_user(app, "own_c", balance=0)
    with app.app_context():
        a = User.query.filter_by(username="own_a").one()
        b = User.query.filter_by(username="own_b").one()
        wallet_service.transfer_points(a, "own_c", "111", "A가 C에게", _key())
        wallet_service.transfer_points(b, "own_c", "222", "B가 C에게", _key())
    _logout(client)
    _login(client, "own_a")
    body = client.get("/wallet").get_data(as_text=True)
    assert "A가 C에게" in body       # 본인 거래
    assert "B가 C에게" not in body   # 타인 거래 비노출(IDOR)


def test_transfer_via_http_success(app, client):
    _make_user(app, "h_recv", balance=0)
    _auth(client, "h_send")
    with app.app_context():
        User.query.filter_by(username="h_send").one()
    # 테스트 준비도 지급 원장과 materialized balance를 함께 만든다.
    with app.app_context():
        u = User.query.filter_by(username="h_send").one()
        u.balance = 1000
        db.session.add(Transfer(
            kind="grant", sender_id=None, receiver_id=u.id, amount=1000,
            memo="test seed", idempotency_key=f"seed-{uuid.uuid4().hex}",
        ))
        db.session.commit()
    page = client.get("/wallet").get_data(as_text=True)
    import re
    key = re.search(r'name="idempotency_key"[^>]*value="([^"]+)"', page).group(1)
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page).group(1)
    r = client.post("/wallet/transfer", data={
        "csrf_token": token, "idempotency_key": key,
        "recipient": "h_recv", "amount": "250", "memo": "http송금",
    }, follow_redirects=False)
    assert r.status_code == 302
    assert _balance(app, "h_send") == 750
    assert _balance(app, "h_recv") == 250


def test_transfer_insufficient_via_http_400(app, client):
    _make_user(app, "hi_recv", balance=0)
    _auth(client, "hi_send")
    page = client.get("/wallet").get_data(as_text=True)
    import re
    key = re.search(r'name="idempotency_key"[^>]*value="([^"]+)"', page).group(1)
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page).group(1)
    r = client.post("/wallet/transfer", data={
        "csrf_token": token, "idempotency_key": key,
        "recipient": "hi_recv", "amount": "50", "memo": "",
    })
    assert r.status_code == 400
    with app.app_context():
        assert Transfer.query.count() == 0


def test_transfer_requires_csrf(app, client):
    _make_user(app, "csrf_recv", balance=0)
    _auth(client, "csrf_send")
    with app.app_context():
        u = User.query.filter_by(username="csrf_send").one()
        u.balance = 500
        db.session.commit()
    app.config["WTF_CSRF_ENABLED"] = True
    r = client.post("/wallet/transfer", data={
        "idempotency_key": _key(), "recipient": "csrf_recv", "amount": "10",
    })
    assert r.status_code == 400
    with app.app_context():
        assert Transfer.query.count() == 0


# ---------- 관리자 grant (AC5.1 / P8 이월) ----------

def test_admin_grant_credits_via_ledger(app, client):
    tid = _make_user(app, "grant_target", balance=0)
    admin_id = _make_user(app, "grant_admin", role="admin")
    with app.app_context():
        admin = db.session.get(User, admin_id)
        admin_service.grant_points(admin, tid, "5000", "초기 지급", _key())
    assert _balance(app, "grant_target") == 5000
    with app.app_context():
        g = Transfer.query.filter_by(kind="grant").one()
        assert g.sender_id is None and g.receiver_id == tid and g.amount == 5000
        assert AuditLog.query.filter_by(actor_type="admin", action="admin_grant", target=tid).count() == 1
        assert wallet_service.ledger_balance(tid) == 5000


def test_admin_grant_is_idempotent_and_conflicts_on_changed_params(app):
    tid = _make_user(app, "grant_idem_target")
    other_id = _make_user(app, "grant_idem_other")
    admin_id = _make_user(app, "grant_idem_admin", role="admin")
    key = _key()
    with app.app_context():
        admin = db.session.get(User, admin_id)
        first = admin_service.grant_points(
            admin, tid, "500", "지급", key
        )
        replay = admin_service.grant_points(
            admin, tid, "500", "지급", key
        )
        assert replay.id == first.id
        with pytest.raises(Conflict):
            admin_service.grant_points(admin, tid, "501", "지급", key)
        with pytest.raises(Conflict):
            admin_service.grant_points(admin, other_id, "500", "지급", key)
        assert Transfer.query.filter_by(kind="grant", idempotency_key=key).count() == 1
        assert db.session.get(User, tid).balance == 500
        assert wallet_service.ledger_balance(tid) == 500
        assert AuditLog.query.filter_by(action="admin_grant", target=tid).count() == 1


def test_admin_cannot_grant_to_admin(app):
    target_id = _make_user(app, "grant_admin_target", role="admin")
    actor_id = _make_user(app, "grant_admin_actor", role="admin")
    with app.app_context():
        with pytest.raises(auth_service.ValidationError):
            admin_service.grant_points(
                db.session.get(User, actor_id), target_id, "100", "", _key()
            )
        assert db.session.get(User, target_id).balance == 0


def test_admin_grant_route_rbac(app, client):
    tid = _make_user(app, "gr_target", balance=0)
    _auth(client, "gr_normal")
    assert client.post(f"/admin/users/{tid}/grant", data={"amount": "100"}).status_code == 403
    with app.app_context():
        assert Transfer.query.count() == 0
        assert db.session.get(User, tid).balance == 0


def test_admin_grant_route_replay_is_applied_once(app, client):
    tid = _make_user(app, "gr_http_target")
    _make_user(app, "gr_http_admin", role="admin")
    _login(client, "gr_http_admin")
    key = _key()
    payload = {
        "amount": "100",
        "memo": "double click",
        "idempotency_key": key,
    }
    assert client.post(
        f"/admin/users/{tid}/grant", data=payload
    ).status_code == 302
    assert client.post(
        f"/admin/users/{tid}/grant", data=payload
    ).status_code == 302
    with app.app_context():
        assert db.session.get(User, tid).balance == 100
        assert Transfer.query.filter_by(
            kind="grant", idempotency_key=key
        ).count() == 1


def test_admin_grant_to_dormant_rejected(app):
    tid = _make_user(app, "gd_target", balance=0, status="dormant")
    admin_id = _make_user(app, "gd_admin", role="admin")
    with app.app_context():
        admin = db.session.get(User, admin_id)
        with pytest.raises(auth_service.ValidationError):
            admin_service.grant_points(admin, tid, "100", "", _key())
        assert Transfer.query.count() == 0


def test_admin_grant_appears_in_transactions_log(app, client):
    tid = _make_user(app, "gl_target", balance=0)
    admin_id = _make_user(app, "gl_admin", role="admin")
    with app.app_context():
        admin = db.session.get(User, admin_id)
        admin_service.grant_points(admin, tid, "700", "지급로그", _key())
    _logout(client)
    _login(client, "gl_admin")
    body = client.get("/admin/transactions").get_data(as_text=True)
    assert "지급로그" in body and "시스템 지급" in body


# ---------- 실제 병렬 송금 경합 (SR-03/AC5.3) ----------

def test_concurrent_transfers_never_overspend(monkeypatch):
    """잔액 100으로 60+60 동시 송금 → 정확히 하나만 성공, 잔액 음수 불가."""
    filename = f"p7-race-{uuid.uuid4().hex}.db"
    monkeypatch.setattr(TestConfig, "SQLALCHEMY_DATABASE_URI", f"sqlite:///{filename}")
    monkeypatch.setattr(
        TestConfig, "SQLALCHEMY_ENGINE_OPTIONS",
        {"connect_args": {"check_same_thread": False, "timeout": 10}},
    )
    race_app = create_app("test")
    db_path = Path(race_app.instance_path) / filename
    try:
        with race_app.app_context():
            db.create_all()
            sender = auth_service.register_user("race_sender", "password123")
            sender.balance = 100
            db.session.add(Transfer(
                kind="grant", sender_id=None, receiver_id=sender.id, amount=100,
                memo="test seed", idempotency_key=f"seed-{uuid.uuid4().hex}",
            ))
            r1 = auth_service.register_user("race_r1", "password123")
            r2 = auth_service.register_user("race_r2", "password123")
            db.session.commit()
            sender_id, r1_id, r2_id = sender.id, r1.id, r2.id

        start = Barrier(2)

        def do_transfer(recipient):
            with race_app.app_context():
                sender = db.session.get(User, sender_id)
                start.wait(timeout=10)
                try:
                    wallet_service.transfer_points(sender, recipient, "60", "race", uuid.uuid4().hex)
                    return "ok"
                except auth_service.ValidationError:
                    return "insufficient"
                except Exception as exc:  # noqa: BLE001
                    return type(exc).__name__

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = sorted(pool.map(do_transfer, ["race_r1", "race_r2"]))

        assert results == ["insufficient", "ok"]  # 정확히 하나 성공
        with race_app.app_context():
            sender = db.session.get(User, sender_id)
            assert sender.balance == 40  # 100 - 60, 음수 없음
            received = (
                db.session.get(User, r1_id).balance + db.session.get(User, r2_id).balance
            )
            assert received == 60
            assert Transfer.query.filter_by(kind="transfer").count() == 1
            assert wallet_service.ledger_balance(sender_id) == 40
            assert wallet_service.ledger_balance(r1_id) == db.session.get(User, r1_id).balance
            assert wallet_service.ledger_balance(r2_id) == db.session.get(User, r2_id).balance
    finally:
        with race_app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()
        if db_path.exists():
            db_path.unlink()


def test_concurrent_same_key_is_applied_once(monkeypatch):
    """같은 요청의 병렬 재전송은 둘 다 같은 결과를 얻고 잔액은 한 번만 변한다."""
    filename = f"p7-idem-race-{uuid.uuid4().hex}.db"
    monkeypatch.setattr(TestConfig, "SQLALCHEMY_DATABASE_URI", f"sqlite:///{filename}")
    monkeypatch.setattr(
        TestConfig, "SQLALCHEMY_ENGINE_OPTIONS",
        {"connect_args": {"check_same_thread": False, "timeout": 10}},
    )
    race_app = create_app("test")
    db_path = Path(race_app.instance_path) / filename
    key = _key()
    try:
        with race_app.app_context():
            db.create_all()
            sender = auth_service.register_user("idem_race_s", "password123")
            sender.balance = 100
            db.session.add(Transfer(
                kind="grant", receiver_id=sender.id, amount=100,
                memo="seed", idempotency_key=f"seed-{_key()}",
            ))
            receiver = auth_service.register_user("idem_race_r", "password123")
            db.session.commit()
            sender_id, receiver_id = sender.id, receiver.id

        start = Barrier(2)

        def send_once():
            with race_app.app_context():
                start.wait(timeout=10)
                result = wallet_service.transfer_points(
                    db.session.get(User, sender_id),
                    "idem_race_r", "60", "race", key,
                )
                return result.id

        with ThreadPoolExecutor(max_workers=2) as pool:
            result_ids = list(pool.map(lambda _: send_once(), range(2)))

        assert result_ids[0] == result_ids[1]
        with race_app.app_context():
            assert Transfer.query.filter_by(kind="transfer").count() == 1
            assert db.session.get(User, sender_id).balance == 40
            assert db.session.get(User, receiver_id).balance == 60
            assert wallet_service.ledger_balance(sender_id) == 40
            assert wallet_service.ledger_balance(receiver_id) == 60
            assert AuditLog.query.filter_by(action="transfer").count() == 1
    finally:
        with race_app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()
        if db_path.exists():
            db_path.unlink()


def test_database_enforces_ledger_guardrails(app):
    sender_id = _make_user(app, "guard_s", balance=100)
    receiver_id = _make_user(app, "guard_r")
    with app.app_context():
        transfer = wallet_service.transfer_points(
            db.session.get(User, sender_id),
            "guard_r", "10", "ok", _key(),
        )
        transfer_id = transfer.id

        with pytest.raises(IntegrityError):
            db.session.execute(
                db.update(Transfer)
                .where(Transfer.id == transfer_id)
                .values(amount=11)
            )
            db.session.commit()
        db.session.rollback()

        with pytest.raises(IntegrityError):
            db.session.execute(
                db.delete(Transfer).where(Transfer.id == transfer_id)
            )
            db.session.commit()
        db.session.rollback()

        db.session.add(Transfer(
            kind="grant", sender_id=None, receiver_id=receiver_id,
            amount=1, memo="", idempotency_key=None,
        ))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()

        db.session.add(Transfer(
            kind="transfer", sender_id=sender_id, receiver_id=receiver_id,
            amount=1, memo="x" * 201, idempotency_key=_key(),
        ))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()

        with pytest.raises(IntegrityError):
            db.session.execute(
                db.update(User)
                .where(User.id == receiver_id)
                .values(balance=1_000_000_000_001)
            )
            db.session.commit()
        db.session.rollback()


def test_concurrent_grant_same_key_is_applied_once(monkeypatch):
    """관리자 지급의 브라우저 재전송도 잔액·원장·감사를 한 번만 만든다."""
    filename = f"p7-grant-race-{uuid.uuid4().hex}.db"
    monkeypatch.setattr(TestConfig, "SQLALCHEMY_DATABASE_URI", f"sqlite:///{filename}")
    monkeypatch.setattr(
        TestConfig, "SQLALCHEMY_ENGINE_OPTIONS",
        {"connect_args": {"check_same_thread": False, "timeout": 10}},
    )
    race_app = create_app("test")
    db_path = Path(race_app.instance_path) / filename
    key = _key()
    try:
        with race_app.app_context():
            db.create_all()
            admin = auth_service.register_user("grant_race_admin", "password123")
            admin.role = "admin"
            target = auth_service.register_user("grant_race_target", "password123")
            db.session.commit()
            admin_id, target_id = admin.id, target.id

        start = Barrier(2)

        def grant_once():
            with race_app.app_context():
                start.wait(timeout=10)
                result = admin_service.grant_points(
                    db.session.get(User, admin_id),
                    target_id, "250", "race grant", key,
                )
                return result.id

        with ThreadPoolExecutor(max_workers=2) as pool:
            result_ids = list(pool.map(lambda _: grant_once(), range(2)))

        assert result_ids[0] == result_ids[1]
        with race_app.app_context():
            assert db.session.get(User, target_id).balance == 250
            assert wallet_service.ledger_balance(target_id) == 250
            assert Transfer.query.filter_by(
                kind="grant", idempotency_key=key
            ).count() == 1
            assert AuditLog.query.filter_by(
                action="admin_grant", target=target_id
            ).count() == 1
    finally:
        with race_app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()
        if db_path.exists():
            db_path.unlink()
