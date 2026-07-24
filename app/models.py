"""SQLAlchemy ORM 모델.

설계 문서 `docs/SYSTEM_DESIGN.ko.md` §5(ERD) 및 제약조건을 단일 구현 기준으로 삼는다.
- 신고 대상 FK 2개 + XOR CHECK + 대상별 중복 UNIQUE
- 송금 kind(transfer|grant) + nullable sender + (sender, idempotency_key) UNIQUE + amount>0
- balance는 원장과 대조 가능한 materialized balance
- dm_room CHECK(user_a_id < user_b_id)
- audit_log actor_type(system|user|admin) + nullable actor_id
"""
import uuid
from datetime import datetime, timezone

from flask_login import UserMixin

from .extensions import db


def _uuid():
    return str(uuid.uuid4())


def utcnow_naive():
    """naive UTC(타임존 미포함). DB 저장·비교를 naive로 일관 유지."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _now():
    return utcnow_naive()


class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    username = db.Column(db.String(32), unique=True, nullable=False)  # SR-01
    password_hash = db.Column(db.String(255), nullable=False)          # V-02
    bio = db.Column(db.String(500), nullable=False, default="")
    role = db.Column(db.String(16), nullable=False, default="user")     # user | admin
    status = db.Column(db.String(16), nullable=False, default="active")  # active | dormant
    # 원장과 대조 가능한 materialized balance (직접 수정 금지 — 서비스 트랜잭션에서만)
    balance = db.Column(db.Integer, nullable=False, default=0)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)  # ⑥
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_now)

    __table_args__ = (
        db.CheckConstraint("role in ('user','admin')", name="ck_user_role"),
        db.CheckConstraint("status in ('active','dormant')", name="ck_user_status"),
        db.CheckConstraint("balance >= 0", name="ck_user_balance_nonneg"),
    )

    @property
    def is_admin(self):
        return self.role == "admin"

    @property
    def is_active(self):
        """Flask-Login의 활성 계정 판정에 휴면 상태를 직접 연결한다."""
        return self.status == "active"


class Product(db.Model):
    __tablename__ = "product"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    title = db.Column(db.String(120), nullable=False, index=True)  # 검색 인덱스
    description = db.Column(db.String(4000), nullable=False, default="")
    price = db.Column(db.Integer, nullable=False)                  # ⑧ 정수·범위
    image_filename = db.Column(db.String(255), nullable=True)  # 난수 파일명
    seller_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(16), nullable=False, default="active")  # active|blocked|deleted
    created_at = db.Column(db.DateTime, nullable=False, default=_now)

    seller = db.relationship("User", backref="products")

    __table_args__ = (
        db.UniqueConstraint(
            "image_filename", name="uq_product_image_filename"
        ),
        db.CheckConstraint(
            "length(trim(title)) between 1 and 120",
            name="ck_product_title_length",
        ),
        db.CheckConstraint(
            "length(description) <= 4000",
            name="ck_product_description_length",
        ),
        db.CheckConstraint(
            "price between 1 and 1000000000",
            name="ck_product_price_range",
        ),
        db.CheckConstraint(
            "status in ('active','blocked','deleted')", name="ck_product_status"
        ),
    )


class Report(db.Model):
    __tablename__ = "report"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    reporter_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    reported_user_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=True)
    reported_product_id = db.Column(
        db.String(36), db.ForeignKey("product.id"), nullable=True
    )
    reason = db.Column(db.String(1000), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")
    resolution = db.Column(db.String(16), nullable=True)  # upheld|reversed|dismissed
    reviewed_by = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_now)

    __table_args__ = (
        db.CheckConstraint(
            "length(trim(reason)) between 1 and 1000",
            name="ck_report_reason_length",
        ),
        # 정확히 하나의 대상만 존재
        db.CheckConstraint(
            "(reported_user_id IS NOT NULL) <> (reported_product_id IS NOT NULL)",
            name="ck_report_exactly_one_target",
        ),
        db.CheckConstraint(
            "status in ('pending','auto_actioned','reviewed','resolved')",
            name="ck_report_status",
        ),
        db.CheckConstraint(
            "resolution is null or resolution in ('upheld','reversed','dismissed')",
            name="ck_report_resolution",
        ),
        db.CheckConstraint(
            "("
            "status in ('pending','auto_actioned') "
            "AND resolution IS NULL AND reviewed_by IS NULL AND reviewed_at IS NULL"
            ") OR ("
            "status = 'reviewed' "
            "AND resolution IS NULL AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL"
            ") OR ("
            "status = 'resolved' "
            "AND resolution in ('upheld','reversed','dismissed') "
            "AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL"
            ")",
            name="ck_report_review_state",
        ),
        db.CheckConstraint(
            "reported_user_id IS NULL OR reporter_id <> reported_user_id",
            name="ck_report_no_self_user",
        ),
        # 대상별 사용자당 1회
        db.UniqueConstraint(
            "reporter_id", "reported_user_id", name="uq_report_user_once"
        ),
        db.UniqueConstraint(
            "reporter_id", "reported_product_id", name="uq_report_product_once"
        ),
    )

    # 관리자 화면 표시용 읽기 전용 관계(스키마 변경 없음 — DDL 미생성).
    reporter = db.relationship(
        "User", foreign_keys=[reporter_id], viewonly=True
    )
    reported_user = db.relationship(
        "User", foreign_keys=[reported_user_id], viewonly=True
    )
    reported_product = db.relationship(
        "Product", foreign_keys=[reported_product_id], viewonly=True
    )
    reviewer = db.relationship(
        "User", foreign_keys=[reviewed_by], viewonly=True
    )


class DMRoom(db.Model):
    __tablename__ = "dm_room"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    user_a_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    user_b_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_now)

    __table_args__ = (
        # 정규화(a<b): 방향 중복 방지 + 자기 자신 DM 금지
        db.CheckConstraint("user_a_id < user_b_id", name="ck_dm_room_order"),
        db.UniqueConstraint("user_a_id", "user_b_id", name="uq_dm_room_pair"),
    )


class ChatMessage(db.Model):
    __tablename__ = "chat_message"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    scope = db.Column(db.String(8), nullable=False)  # global | dm
    dm_room_id = db.Column(db.String(36), db.ForeignKey("dm_room.id"), nullable=True)
    sender_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.String(500), nullable=False)  # ⑬ 길이 제한
    created_at = db.Column(db.DateTime, nullable=False, default=_now)

    __table_args__ = (
        db.CheckConstraint(
            "(scope = 'global' AND dm_room_id IS NULL) "
            "OR (scope = 'dm' AND dm_room_id IS NOT NULL)",
            name="ck_chat_scope_room",
        ),
    )


class Transfer(db.Model):
    """불변 원장(append-only). balance는 여기서 파생/대조."""

    __tablename__ = "transfer"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    kind = db.Column(db.String(10), nullable=False, default="transfer")  # transfer|grant
    sender_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=True)
    receiver_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    memo = db.Column(db.String(200), nullable=False, default="")
    idempotency_key = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_now)

    __table_args__ = (
        db.CheckConstraint("amount > 0", name="ck_transfer_amount_pos"),
        db.CheckConstraint(
            "(kind = 'transfer' AND sender_id IS NOT NULL "
            "AND sender_id <> receiver_id AND idempotency_key IS NOT NULL) "
            "OR (kind = 'grant' AND sender_id IS NULL)",
            name="ck_transfer_kind",
        ),
        db.CheckConstraint(
            "idempotency_key IS NULL OR "
            "length(idempotency_key) BETWEEN 16 AND 64",
            name="ck_transfer_idempotency_length",
        ),
        # 발신자별 멱등 키
        db.UniqueConstraint(
            "sender_id", "idempotency_key", name="uq_transfer_idempotency"
        ),
    )

    # 관리자 거래 로그 표시용 읽기 전용 관계(스키마 변경 없음).
    sender = db.relationship("User", foreign_keys=[sender_id], viewonly=True)
    receiver = db.relationship("User", foreign_keys=[receiver_id], viewonly=True)


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    actor_type = db.Column(db.String(8), nullable=False)  # system|user|admin
    actor_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(64), nullable=False)
    target = db.Column(db.String(128), nullable=False, default="")
    detail = db.Column(db.String(1000), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=_now)

    __table_args__ = (
        db.CheckConstraint(
            "(actor_type = 'system' AND actor_id IS NULL) "
            "OR (actor_type in ('user','admin') AND actor_id IS NOT NULL)",
            name="ck_audit_actor",
        ),
    )

    # 관리자 감사 로그 표시용 읽기 전용 관계(스키마 변경 없음).
    actor = db.relationship("User", foreign_keys=[actor_id], viewonly=True)


def write_audit(actor_type, action, actor_id=None, target="", detail=""):
    """감사 로그 헬퍼(SR-05). 커밋은 호출측 트랜잭션에서 수행."""
    entry = AuditLog(
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        target=str(target)[:128],
        detail=str(detail)[:1000],
    )
    db.session.add(entry)
    return entry
