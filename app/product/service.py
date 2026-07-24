"""상품 서비스 (P4) — 검증·이미지 처리·가시성 쿼리·소유권.

- ⑧ 서버측 입력 검증(가격 정수·범위, 길이)   - ⑨ XSS(출력 이스케이프+입력 검증)
- ⑩ 로그인 사용자만 등록·수정·삭제(라우트)   - ⑪ 소유자 검증(IDOR)
- V-18 이미지: 확장자+Pillow 디코딩·재인코딩(메타/페이로드 제거)+난수명+치수 제한
- AC2.6 차단/삭제 상품·휴면 판매자 상품 공개 비노출
- AC6.2 검색 파라미터 바인딩 + 정렬 허용목록(㉒)
"""
import os
import re
import uuid
import warnings

from flask import current_app
from werkzeug.exceptions import NotFound, Forbidden
from PIL import Image, UnidentifiedImageError

from ..extensions import db
from ..models import User, Product, write_audit
from ..auth.service import ValidationError

_PIL_ERRORS = (
    UnidentifiedImageError,
    OSError,
    Image.DecompressionBombError,
    Image.DecompressionBombWarning,
)
_IMAGE_FILENAME_RE = re.compile(r"^[0-9a-f]{32}\.(?:jpg|png|webp)$")


# ---------- 입력 검증 ----------

def clean_title(title: str) -> str:
    title = (title or "").strip()
    limit = current_app.config["PRODUCT_TITLE_MAX"]
    if not title:
        raise ValidationError("상품명을 입력하세요.")
    if len(title) > limit:
        raise ValidationError(f"상품명은 최대 {limit}자까지 입력할 수 있습니다.")
    return title


def clean_description(description: str) -> str:
    description = (description or "").strip()
    limit = current_app.config["PRODUCT_DESC_MAX"]
    if len(description) > limit:
        raise ValidationError(f"설명은 최대 {limit}자까지 입력할 수 있습니다.")
    return description


def parse_price(raw) -> int:
    raw = str(raw if raw is not None else "").strip()
    if not re.fullmatch(r"\d+", raw):
        raise ValidationError("가격은 0보다 큰 정수여야 합니다.")
    price = int(raw)
    lo = current_app.config["PRICE_MIN"]
    hi = current_app.config["PRICE_MAX"]
    if not (lo <= price <= hi):
        raise ValidationError(f"가격은 {lo}~{hi:,}원 범위여야 합니다.")
    return price


# ---------- 이미지 처리 (V-18) ----------

def save_image(file_storage):
    """업로드 이미지를 검증·재인코딩하여 난수 파일명으로 저장. 없으면 None."""
    if file_storage is None or not getattr(file_storage, "filename", ""):
        return None

    cfg = current_app.config
    ext = (
        file_storage.filename.rsplit(".", 1)[-1].lower()
        if "." in file_storage.filename
        else ""
    )
    if ext not in cfg["ALLOWED_IMAGE_EXTENSIONS"]:
        raise ValidationError("허용되지 않은 이미지 형식입니다(jpg/png/webp).")
    declared_mime = (getattr(file_storage, "mimetype", "") or "").lower()
    allowed_mimes = {
        mime
        for values in cfg["IMAGE_MIME_BY_FORMAT"].values()
        for mime in values
    }
    if declared_mime not in allowed_mimes:
        raise ValidationError("이미지 MIME 형식이 올바르지 않습니다.")

    stream = file_storage.stream

    def _validate_dimensions(width, height):
        max_dim = cfg["MAX_IMAGE_DIMENSION"]
        max_pixels = cfg["MAX_IMAGE_PIXELS"]
        if (
            width <= 0
            or height <= 0
            or width > max_dim
            or height > max_dim
            or width * height > max_pixels
        ):
            raise ValidationError(
                f"이미지는 최대 {max_dim}px, {max_pixels:,}픽셀 이하여야 합니다."
            )

    clean = None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)

            # 1) 전체 픽셀 로드 전에 헤더의 포맷·치수부터 제한한다.
            stream.seek(0)
            with Image.open(stream) as probe:
                fmt = probe.format
                if fmt not in cfg["ALLOWED_IMAGE_FORMATS"]:
                    raise ValidationError(
                        "허용되지 않은 이미지 형식입니다(jpg/png/webp)."
                    )
                _validate_dimensions(*probe.size)
                probe.verify()

            if declared_mime not in cfg["IMAGE_MIME_BY_FORMAT"][fmt]:
                raise ValidationError("파일 내용과 MIME 형식이 일치하지 않습니다.")

            # 2) verify 후 재오픈하고 제한을 다시 확인한 뒤 픽셀을 로드한다.
            stream.seek(0)
            with Image.open(stream) as image:
                if image.format != fmt:
                    raise ValidationError("이미지 형식이 일관되지 않습니다.")
                _validate_dimensions(*image.size)
                image.load()
                # 3) 픽셀만 복사해 EXIF·임베디드 페이로드를 제거한다.
                if fmt == "JPEG":
                    clean = image.convert("RGB")
                else:  # PNG / WEBP: 알파 보존
                    clean = (
                        image.convert("RGBA")
                        if image.mode in ("RGBA", "LA", "P")
                        else image.convert("RGB")
                    )
    except _PIL_ERRORS as exc:
        raise ValidationError("올바른 이미지 파일이 아닙니다.") from exc

    new_name = uuid.uuid4().hex + cfg["IMAGE_EXT_BY_FORMAT"][fmt]
    destination = os.path.join(cfg["UPLOAD_FOLDER"], new_name)
    descriptor = None
    try:
        # O_EXCL로 심볼릭 링크/충돌 덮어쓰기를 막고 소유자 전용 권한으로 생성한다.
        descriptor = os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            clean.save(output, format=fmt)
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        _remove_image(new_name)
        raise
    finally:
        if clean is not None:
            clean.close()
    return new_name


def is_safe_image_filename(filename):
    return bool(_IMAGE_FILENAME_RE.fullmatch(filename or ""))


def _remove_image(filename):
    if not is_safe_image_filename(filename):
        return
    try:
        os.remove(os.path.join(current_app.config["UPLOAD_FOLDER"], filename))
    except OSError:
        pass  # best-effort


# ---------- 생성/수정/삭제 (원자적: 검증→변경→감사→커밋) ----------

def create_product(user: User, title, description, price_raw, image_file) -> Product:
    title = clean_title(title)
    description = clean_description(description)
    price = parse_price(price_raw)
    image_filename = None
    try:
        image_filename = save_image(image_file)
        product = Product(
            title=title,
            description=description,
            price=price,
            image_filename=image_filename,
            seller_id=user.id,  # seller_id는 세션 사용자로만 결정
            status="active",
        )
        db.session.add(product)
        db.session.flush()  # PK 확정 후 감사 target 기록
        write_audit("user", "product_create", actor_id=user.id, target=product.id)
        db.session.commit()
        return product
    except Exception:
        db.session.rollback()
        _remove_image(image_filename)
        raise


def update_product(product: Product, title, description, price_raw, image_file) -> Product:
    title = clean_title(title)
    description = clean_description(description)
    price = parse_price(price_raw)
    new_image = None
    old_image = product.image_filename
    try:
        new_image = save_image(image_file)
        product.title = title
        product.description = description
        product.price = price
        if new_image:
            product.image_filename = new_image
        write_audit(
            "user", "product_update", actor_id=product.seller_id, target=product.id
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        _remove_image(new_image)
        raise
    if new_image:
        # DB가 새 파일을 가리키는 것이 확정된 뒤에만 이전 파일을 제거한다.
        _remove_image(old_image)
    return product


def soft_delete(product: Product, user: User) -> None:
    product.status = "deleted"  # soft delete(관리자 복구 가능) — 이미지 파일은 보존
    write_audit("user", "product_delete", actor_id=user.id, target=product.id)
    db.session.commit()


# ---------- 조회/가시성 ----------

def _visible_query():
    """active 상품 + active 판매자만 공개(AC2.6)."""
    return (
        Product.query.join(User, Product.seller_id == User.id)
        .filter(Product.status == "active", User.status == "active")
    )


def _apply_sort(query, sort):
    if sort == "price_asc":
        return query.order_by(Product.price.asc(), Product.created_at.desc())
    if sort == "price_desc":
        return query.order_by(Product.price.desc(), Product.created_at.desc())
    return query.order_by(Product.created_at.desc())  # newest(기본)


def normalize_sort(sort):
    if sort not in current_app.config["PRODUCT_SORT_OPTIONS"]:
        return "newest"
    return sort


def clean_search_query(q):
    q = (q or "").strip()
    if len(q) > current_app.config["SEARCH_QUERY_MAX"]:
        raise ValidationError(
            f"검색어는 최대 {current_app.config['SEARCH_QUERY_MAX']}자까지 입력할 수 있습니다."
        )
    return q


def list_products(page: int, q: str = None, sort: str = "newest"):
    sort = normalize_sort(sort)
    q = clean_search_query(q)
    query = _visible_query()
    if q:
        query = query.filter(
            db.or_(
                Product.title.icontains(q, autoescape=True),
                Product.description.icontains(q, autoescape=True),
            )
        )
    query = _apply_sort(query, sort)
    return query.paginate(
        page=page, per_page=current_app.config["PRODUCTS_PER_PAGE"], error_out=False
    )


def get_product_detail_or_404(product_id: str, viewer) -> Product:
    """공개 상품, 차단 상태인 본인 상품, 관리자 감사 조회를 허용한다."""
    product = db.session.get(Product, product_id)
    if product is None:
        raise NotFound()
    is_admin = (
        getattr(viewer, "is_authenticated", False)
        and getattr(viewer, "is_admin", False)
    )
    if product.status == "deleted" and not is_admin:
        raise NotFound()
    seller = db.session.get(User, product.seller_id)
    publicly_visible = (
        product.status == "active"
        and seller is not None
        and seller.status == "active"
    )
    owner_visible = (
        getattr(viewer, "is_authenticated", False)
        and viewer.id == product.seller_id
    )
    if not (publicly_visible or owner_visible or is_admin):
        raise NotFound()
    return product


def authorize_image_or_404(filename, viewer) -> Product:
    """상품 가시성과 동일한 정책으로 이미지 접근을 허용한다."""
    if not is_safe_image_filename(filename):
        raise NotFound()
    product = Product.query.filter_by(image_filename=filename).first()
    if product is None:
        raise NotFound()
    seller = db.session.get(User, product.seller_id)
    publicly_visible = (
        product.status == "active"
        and seller is not None
        and seller.status == "active"
    )
    owner_visible = (
        getattr(viewer, "is_authenticated", False)
        and viewer.id == product.seller_id
        and product.status != "deleted"
    )
    admin_visible = (
        getattr(viewer, "is_authenticated", False)
        and getattr(viewer, "is_admin", False)
    )
    if not (publicly_visible or owner_visible or admin_visible):
        raise NotFound()
    return product


def own_products(user_id: str):
    """내 상품(삭제 제외, active+blocked 포함)."""
    return (
        Product.query.filter(
            Product.seller_id == user_id, Product.status != "deleted"
        )
        .order_by(Product.created_at.desc())
        .all()
    )


def get_owned_product_or_error(product_id: str, user: User) -> Product:
    """소유권 검증(IDOR): 미존재/삭제→404, 타인 소유→403."""
    product = db.session.get(Product, product_id)
    if product is None or product.status == "deleted":
        raise NotFound()
    if product.seller_id != user.id:
        raise Forbidden()
    return product
