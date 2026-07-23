"""사용자 프로필 서비스 (P3).

- 소개글(bio) 서버측 검증·수정 (①, V-06)
- 공개 프로필 조회 시 민감정보(password_hash/balance/role 등) 비노출 (SR-02)
"""
from flask import current_app
from werkzeug.exceptions import NotFound

from ..extensions import db
from ..models import User, Product
from ..auth.service import ValidationError


def validate_bio(bio: str) -> str:
    bio = (bio or "").strip()
    hi = current_app.config["BIO_MAX"]
    if len(bio) > hi:
        raise ValidationError(f"소개글은 최대 {hi}자까지 입력할 수 있습니다.")
    return bio


def update_bio(user: User, bio: str) -> None:
    """소개글 수정. 커밋은 호출측(라우트)에서 수행."""
    user.bio = validate_bio(bio)


def get_user_or_404(user_id: str) -> User:
    user = db.session.get(User, user_id)
    if user is None:
        raise NotFound()
    return user


def active_product_count(user_id: str) -> int:
    return Product.query.filter_by(seller_id=user_id, status="active").count()


def public_profile(user: User) -> dict:
    """공개 프로필용 화이트리스트 필드만 반환(민감정보 제외)."""
    return {
        "username": user.username,
        "bio": user.bio,
        "created_at": user.created_at,
        # 휴면 판매자의 상품은 active 상태여도 일반 화면에서 집계하지 않는다(AC2.6).
        "active_products": (
            active_product_count(user.id) if user.status == "active" else 0
        ),
    }
