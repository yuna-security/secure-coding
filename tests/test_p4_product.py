"""P4 상품 등록·조회·관리 + R6 검색 테스트.

체크리스트/설계 매핑:
- ⑧ 가격/길이 서버측 검증  - ⑨ XSS 이스케이프  - ⑩ 로그인 사용자만 등록/수정/삭제
- ⑪ 소유자 검증(IDOR, T-206)  - V-18 이미지 업로드 검증  - AC2.5 페이지네이션
- AC2.6 차단/삭제/휴면 판매자 상품 비노출  - AC6.2 검색 파라미터/정렬 허용목록
"""
import io
import re
import time
from pathlib import Path

import pytest
from PIL import Image
from sqlalchemy.exc import IntegrityError
from werkzeug.datastructures import FileStorage

from app.auth import service as auth_service
from app.extensions import db
from app.models import AuditLog, Product, User
from app.product import service as product_service


# ---------- 헬퍼 ----------

def _register(client, username, password="password123"):
    return client.post("/register", data={"username": username, "password": password})


def _login(client, username, password="password123"):
    return client.post("/login", data={"username": username, "password": password})


def _logout(client):
    client.post("/logout")


def _auth(client, username):
    # 이미 로그인돼 있으면 register/login이 리다이렉트되므로 먼저 로그아웃(사용자 전환 보장)
    _logout(client)
    _register(client, username)
    _login(client, username)


def _uid(username):
    return User.query.filter_by(username=username).one().id


def _png(color=(255, 0, 0), size=(12, 12), fmt="PNG"):
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format=fmt)
    buf.seek(0)
    return buf


def _upload(stream=None, filename="photo.png", content_type="image/png"):
    return FileStorage(
        stream=stream or _png(),
        filename=filename,
        content_type=content_type,
    )


def _create_via_http(client, title="상품", price="1000", description="설명", image=None):
    data = {"title": title, "price": price, "description": description}
    if image is not None:
        data["image"] = image
    return client.post(
        "/products/new", data=data, content_type="multipart/form-data",
        follow_redirects=False,
    )


# ---------- 등록: 인증/검증 ----------

def test_new_requires_login(client):
    r = client.get("/products/new", follow_redirects=False)
    assert r.status_code in (302, 401)
    r = client.post("/products/new", data={"title": "x", "price": "10"}, follow_redirects=False)
    assert r.status_code in (302, 401)


def test_create_product_success(app, client):
    _auth(client, "seller")
    r = _create_via_http(client, title="자전거", price="50000", description="좋은 자전거")
    assert r.status_code == 302
    with app.app_context():
        p = Product.query.filter_by(title="자전거").one()
        assert p.price == 50000 and p.status == "active"
        assert p.seller_id == _uid("seller")
        assert AuditLog.query.filter_by(action="product_create", target=p.id).count() == 1


@pytest.mark.parametrize("price", ["abc", "0", "-5", "1.5", "", "9999999999"])
def test_create_invalid_price_returns_400(app, client, price):
    _auth(client, "seller_p")
    r = _create_via_http(client, title="상품", price=price)
    assert r.status_code == 400
    with app.app_context():
        assert Product.query.count() == 0


def test_create_title_required_and_length(app, client):
    _auth(client, "seller_t")
    assert _create_via_http(client, title="", price="10").status_code == 400
    assert _create_via_http(client, title="x" * 121, price="10").status_code == 400
    with app.app_context():
        assert Product.query.count() == 0


def test_create_description_too_long_returns_400(app, client):
    _auth(client, "seller_d")
    r = _create_via_http(client, title="상품", price="10", description="x" * 4001)
    assert r.status_code == 400
    with app.app_context():
        assert Product.query.count() == 0


def test_create_ignores_forged_seller_id(app, client):
    with app.app_context():
        other = auth_service.register_user("victim_seller", "password123")
        other_id = other.id
    _auth(client, "attacker_seller")
    client.post(
        "/products/new",
        data={"title": "위조", "price": "100", "description": "d", "seller_id": other_id},
        content_type="multipart/form-data",
    )
    with app.app_context():
        p = Product.query.filter_by(title="위조").one()
        assert p.seller_id == _uid("attacker_seller")  # 위조 seller_id 무시


# ---------- 이미지 업로드 (V-18) ----------

def test_create_with_valid_image_and_serving(app, client):
    _auth(client, "img_seller")
    r = _create_via_http(
        client, title="사진상품", price="100", image=(_png(), "photo.png")
    )
    assert r.status_code == 302
    with app.app_context():
        p = Product.query.filter_by(title="사진상품").one()
        assert re.fullmatch(r"[0-9a-f]{32}\.png", p.image_filename)
        fname = p.image_filename
    served = client.get(f"/uploads/{fname}")
    assert served.status_code == 200
    assert served.headers["Content-Type"].startswith("image/")
    assert served.headers["Cache-Control"] == "private, no-store"


def test_create_rejects_fake_image(app, client):
    _auth(client, "fake_img")
    fake = io.BytesIO(b"this is not an image")
    r = _create_via_http(client, title="가짜", price="100", image=(fake, "evil.png"))
    assert r.status_code == 400
    with app.app_context():
        assert Product.query.count() == 0


def test_create_rejects_disallowed_extension(app, client):
    _auth(client, "bad_ext")
    r = _create_via_http(
        client, title="확장자", price="100", image=(io.BytesIO(b"x"), "note.txt")
    )
    assert r.status_code == 400
    with app.app_context():
        assert Product.query.count() == 0


def test_create_rejects_mime_spoof_and_oversized_dimensions(app, client):
    _auth(client, "img_limits")
    spoofed = _create_via_http(
        client,
        title="MIME 위조",
        price="100",
        image=(_png(), "photo.png", "text/plain"),
    )
    assert spoofed.status_code == 400

    oversized = _create_via_http(
        client,
        title="치수 초과",
        price="100",
        image=(_png(size=(4097, 1)), "wide.png", "image/png"),
    )
    assert oversized.status_code == 400
    with app.app_context():
        assert Product.query.count() == 0
        assert not list(Path(app.config["UPLOAD_FOLDER"]).iterdir())


def test_image_visibility_follows_product_and_seller_state(app, client):
    _auth(client, "image_owner")
    _create_via_http(
        client, title="접근통제 사진", price="100", image=(_png(), "photo.png")
    )
    with app.app_context():
        product = Product.query.filter_by(title="접근통제 사진").one()
        product_id, filename = product.id, product.image_filename

    _logout(client)
    assert client.get(f"/uploads/{filename}").status_code == 200

    with app.app_context():
        db.session.get(Product, product_id).status = "blocked"
        db.session.commit()
    assert client.get(f"/uploads/{filename}").status_code == 404

    _login(client, "image_owner")
    assert client.get(f"/uploads/{filename}").status_code == 200
    with app.app_context():
        db.session.get(Product, product_id).status = "deleted"
        db.session.commit()
    assert client.get(f"/uploads/{filename}").status_code == 404
    assert client.get("/uploads/not-a-generated-name.png").status_code == 404


def test_image_create_commit_failure_removes_orphan(app, monkeypatch):
    with app.app_context():
        seller = auth_service.register_user("rollback_create", "password123")
        upload_dir = Path(app.config["UPLOAD_FOLDER"])

        def fail_commit():
            raise RuntimeError("forced commit failure")

        monkeypatch.setattr(db.session, "commit", fail_commit)
        with pytest.raises(RuntimeError):
            product_service.create_product(
                seller, "롤백 상품", "설명", "100", _upload()
            )
        assert Product.query.count() == 0
        assert not list(upload_dir.iterdir())


def test_image_update_commit_failure_preserves_old_file(app, monkeypatch):
    with app.app_context():
        seller = auth_service.register_user("rollback_update", "password123")
        product = product_service.create_product(
            seller, "원본 상품", "설명", "100", _upload()
        )
        product_id, old_name = product.id, product.image_filename
        upload_dir = Path(app.config["UPLOAD_FOLDER"])
        assert (upload_dir / old_name).is_file()

        def fail_commit():
            raise RuntimeError("forced commit failure")

        monkeypatch.setattr(db.session, "commit", fail_commit)
        with pytest.raises(RuntimeError):
            product_service.update_product(
                product, "변경 상품", "변경", "200", _upload(_png((0, 0, 255)))
            )
        persisted = db.session.get(Product, product_id)
        assert persisted.title == "원본 상품"
        assert persisted.image_filename == old_name
        assert {path.name for path in upload_dir.iterdir()} == {old_name}


def test_image_update_replaces_file_only_after_successful_commit(app):
    with app.app_context():
        seller = auth_service.register_user("replace_image", "password123")
        product = product_service.create_product(
            seller, "교체 전", "설명", "100", _upload()
        )
        old_name = product.image_filename
        upload_dir = Path(app.config["UPLOAD_FOLDER"])

        product_service.update_product(
            product,
            "교체 후",
            "설명",
            "200",
            _upload(_png((0, 255, 0))),
        )
        new_name = product.image_filename
        assert new_name != old_name
        assert not (upload_dir / old_name).exists()
        assert (upload_dir / new_name).is_file()


# ---------- 공개 목록/상세/가시성 ----------

def test_list_public_and_pagination(app, client):
    with app.app_context():
        seller = auth_service.register_user("bulk_seller", "password123")
        for i in range(25):
            db.session.add(
                Product(title=f"item{i}", description="d", price=100 + i, seller_id=seller.id)
            )
        db.session.commit()
    # 익명 접근 가능
    r1 = client.get("/products")
    assert r1.status_code == 200
    r1b = client.get("/products?page=1")
    r2 = client.get("/products?page=2")
    # 20 + 5
    assert r1b.get_data(as_text=True).count('class="product-card"') == 20
    assert r2.get_data(as_text=True).count('class="product-card"') == 5


def test_list_hides_blocked_deleted_and_dormant_seller(app, client):
    with app.app_context():
        active_seller = auth_service.register_user("vis_seller", "password123")
        dormant_seller = auth_service.register_user("dorm_seller", "password123")
        dormant_seller.status = "dormant"
        db.session.add_all([
            Product(title="visible_item", description="d", price=100, seller_id=active_seller.id, status="active"),
            Product(title="blocked_item", description="d", price=100, seller_id=active_seller.id, status="blocked"),
            Product(title="deleted_item", description="d", price=100, seller_id=active_seller.id, status="deleted"),
            Product(title="dormant_item", description="d", price=100, seller_id=dormant_seller.id, status="active"),
        ])
        db.session.commit()
    body = client.get("/products").get_data(as_text=True)
    assert "visible_item" in body
    assert "blocked_item" not in body
    assert "deleted_item" not in body
    assert "dormant_item" not in body


def test_detail_visibility(app, client):
    with app.app_context():
        seller = auth_service.register_user("detail_seller", "password123")
        active = Product(title="active_d", description="d", price=100, seller_id=seller.id, status="active")
        blocked = Product(title="blocked_d", description="d", price=100, seller_id=seller.id, status="blocked")
        db.session.add_all([active, blocked])
        db.session.commit()
        active_id, blocked_id = active.id, blocked.id
    assert client.get(f"/products/{active_id}").status_code == 200
    assert client.get(f"/products/{blocked_id}").status_code == 404
    _login(client, "detail_seller")
    assert client.get(f"/products/{blocked_id}").status_code == 200
    assert client.get("/products/unknown-id").status_code == 404


# ---------- 수정/삭제: 소유권(IDOR) ----------

def _make_owned_product(app, owner_username):
    with app.app_context():
        owner = User.query.filter_by(username=owner_username).one()
        p = Product(title="원본", description="d", price=100, seller_id=owner.id)
        db.session.add(p)
        db.session.commit()
        return p.id


def test_edit_owner_success_and_nonowner_forbidden(app, client):
    _auth(client, "owner1")
    pid = _make_owned_product(app, "owner1")
    # 소유자 수정 성공
    r = client.post(
        f"/products/{pid}/edit",
        data={"title": "수정됨", "price": "200", "description": "new"},
        content_type="multipart/form-data",
    )
    assert r.status_code == 302
    with app.app_context():
        assert db.session.get(Product, pid).title == "수정됨"
        assert db.session.get(Product, pid).price == 200
    # 타인 수정 시도 → 403
    _auth(client, "intruder1")
    r2 = client.post(
        f"/products/{pid}/edit",
        data={"title": "탈취", "price": "1", "description": "x"},
        content_type="multipart/form-data",
    )
    assert r2.status_code == 403
    assert client.get(f"/products/{pid}/edit").status_code == 403
    with app.app_context():
        assert db.session.get(Product, pid).title == "수정됨"  # 변경 안 됨


def test_delete_owner_soft_deletes_and_nonowner_forbidden(app, client):
    _auth(client, "owner2")
    pid = _make_owned_product(app, "owner2")
    r = client.post(f"/products/{pid}/delete")
    assert r.status_code == 302
    with app.app_context():
        assert db.session.get(Product, pid).status == "deleted"
    # 공개 목록·상세에서 사라짐
    assert client.get(f"/products/{pid}").status_code == 404
    # 타인 삭제 시도 → 403(대상은 이미 deleted라 404가 될 수 있으니 새 상품으로 검증)
    _auth(client, "owner3")
    pid3 = _make_owned_product(app, "owner3")
    _auth(client, "intruder2")
    assert client.post(f"/products/{pid3}/delete").status_code == 403
    with app.app_context():
        assert db.session.get(Product, pid3).status == "active"


def test_mine_lists_active_and_blocked_excludes_deleted(app, client):
    _auth(client, "mine_seller")
    with app.app_context():
        uid = _uid("mine_seller")
        db.session.add_all([
            Product(title="mine_active", description="d", price=1, seller_id=uid, status="active"),
            Product(title="mine_blocked", description="d", price=1, seller_id=uid, status="blocked"),
            Product(title="mine_deleted", description="d", price=1, seller_id=uid, status="deleted"),
        ])
        db.session.commit()
    body = client.get("/me/products").get_data(as_text=True)
    assert "mine_active" in body and "mine_blocked" in body
    assert "mine_deleted" not in body


# ---------- 검색 (R6) ----------

def test_search_matches_active_only(app, client):
    with app.app_context():
        seller = auth_service.register_user("search_seller", "password123")
        db.session.add_all([
            Product(title="빨간 자전거", description="튼튼함", price=100, seller_id=seller.id),
            Product(title="파란 노트북", description="가벼움", price=200, seller_id=seller.id),
            Product(title="자전거 헬멧", description="d", price=10, seller_id=seller.id, status="blocked"),
        ])
        db.session.commit()
    body = client.get("/products/search?q=자전거").get_data(as_text=True)
    assert "빨간 자전거" in body
    assert "파란 노트북" not in body
    assert "자전거 헬멧" not in body  # blocked 제외


def test_search_invalid_sort_defaults_no_error(app, client):
    with app.app_context():
        seller = auth_service.register_user("sort_seller", "password123")
        db.session.add(Product(title="정렬상품", description="d", price=100, seller_id=seller.id))
        db.session.commit()
    r = client.get("/products?sort=bogus'; DROP TABLE product;--")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "정렬상품" in body
    assert '<option value="newest" selected>' in body
    assert "DROP TABLE" not in body


def test_search_escapes_sql_wildcards_and_rejects_overlong_query(app, client):
    with app.app_context():
        seller = auth_service.register_user("literal_search", "password123")
        db.session.add(
            Product(title="일반 상품", description="wildcard 없음", price=100, seller_id=seller.id)
        )
        db.session.commit()
    literal = client.get("/products/search?q=%25")
    assert literal.status_code == 200
    assert "일반 상품" not in literal.get_data(as_text=True)
    assert client.get(f"/products/search?q={'x' * 101}").status_code == 400


def test_search_1000_seed_items_completes_within_two_seconds(app, client):
    with app.app_context():
        seller = auth_service.register_user("perf_search", "password123")
        db.session.add_all(
            [
                Product(
                    title=f"성능 상품 {index}",
                    description="검색 성능 기준 데이터",
                    price=index + 1,
                    seller_id=seller.id,
                )
                for index in range(1000)
            ]
        )
        db.session.commit()
    started = time.perf_counter()
    response = client.get("/products/search?q=성능&sort=price_asc")
    elapsed = time.perf_counter() - started
    assert response.status_code == 200
    assert elapsed < 2.0


def test_product_database_constraints_are_enforced(app):
    with app.app_context():
        seller = auth_service.register_user("db_product", "password123")
        db.session.add(
            Product(title="   ", description="d", price=100, seller_id=seller.id)
        )
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()

        db.session.add(
            Product(
                title="설명 초과",
                description="x" * 4001,
                price=100,
                seller_id=seller.id,
            )
        )
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()

        db.session.add(
            Product(
                title="가격 초과",
                description="d",
                price=1_000_000_001,
                seller_id=seller.id,
            )
        )
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()

        generated_name = f"{'a' * 32}.png"
        db.session.add_all(
            [
                Product(
                    title="첫 상품",
                    description="d",
                    price=100,
                    seller_id=seller.id,
                    image_filename=generated_name,
                ),
                Product(
                    title="둘째 상품",
                    description="d",
                    price=100,
                    seller_id=seller.id,
                    image_filename=generated_name,
                ),
            ]
        )
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


# ---------- XSS ----------

def test_product_xss_escaped_in_list_and_detail(app, client):
    with app.app_context():
        seller = auth_service.register_user("xss_seller", "password123")
        p = Product(
            title="<script>alert(1)</script>",
            description="<img src=x onerror=alert(2)>",
            price=100,
            seller_id=seller.id,
        )
        db.session.add(p)
        db.session.commit()
        pid = p.id
    list_body = client.get("/products").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in list_body
    assert "&lt;script&gt;" in list_body
    detail_body = client.get(f"/products/{pid}").get_data(as_text=True)
    assert "<img src=x onerror=alert(2)>" not in detail_body


# ---------- CSRF ----------

def test_new_requires_csrf(app, client):
    _auth(client, "csrf_seller")
    app.config["WTF_CSRF_ENABLED"] = True
    r = client.post(
        "/products/new",
        data={"title": "t", "price": "100", "description": "d"},
        content_type="multipart/form-data",
    )
    assert r.status_code == 400
    with app.app_context():
        assert Product.query.count() == 0


def test_delete_requires_csrf(app, client):
    _auth(client, "csrf_del")
    pid = _make_owned_product(app, "csrf_del")
    app.config["WTF_CSRF_ENABLED"] = True
    r = client.post(f"/products/{pid}/delete")
    assert r.status_code == 400
    with app.app_context():
        assert db.session.get(Product, pid).status == "active"


def test_edit_requires_csrf_and_request_size_is_limited(app, client):
    _auth(client, "csrf_edit")
    pid = _make_owned_product(app, "csrf_edit")
    app.config["WTF_CSRF_ENABLED"] = True
    edit = client.post(
        f"/products/{pid}/edit",
        data={"title": "변조", "price": "100", "description": "d"},
        content_type="multipart/form-data",
    )
    assert edit.status_code == 400

    # 앱 전역 5MB 제한이 상품 업로드에도 실제 적용되는지 확인한다.
    too_large = io.BytesIO(b"x" * (5 * 1024 * 1024 + 1))
    upload = client.post(
        "/products/new",
        data={
            "csrf_token": "",
            "title": "큰 파일",
            "price": "100",
            "description": "d",
            "image": (too_large, "large.png"),
        },
        content_type="multipart/form-data",
    )
    assert upload.status_code == 413
