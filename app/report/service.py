"""신고·차단 서비스 (P6, R4).

- ⑱ 신고 사유 서버측 검증  - ⑲ 로그인 사용자만(라우트)  - ⑳ 감사 로그
- ㉑/SR-04 남용 방지: 자기 신고 금지 · 대상별 1회(UNIQUE) · 활성 사용자 신고만 집계
- AC4.3/4.4 임계치 자동 조치: 상품 차단 / 사용자 휴면, 시스템 감사(actor_type=system)
- 신고 접수와 임계치 자동 조치를 단일 트랜잭션으로 원자 처리
"""
from flask import current_app
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import NotFound

from ..extensions import db
from ..models import User, Product, Report, write_audit
from ..auth.service import ValidationError


def validate_reason(reason: str) -> str:
    reason = (reason or "").strip()
    if not reason:
        raise ValidationError("신고 사유를 입력하세요.")
    limit = current_app.config["REPORT_REASON_MAX"]
    if len(reason) > limit:
        raise ValidationError(f"신고 사유는 최대 {limit}자까지 입력할 수 있습니다.")
    return reason


def _visible_product(product_id):
    """공개적으로 볼 수 있는(active 상품 + active 판매자) 상품만 신고 대상."""
    return (
        Product.query.join(User, Product.seller_id == User.id)
        .filter(
            Product.id == product_id,
            Product.status == "active",
            User.status == "active",
        )
        .first()
    )


def _active_report_count(*, product_id=None, user_id=None) -> int:
    """활성 사용자가 제출한 아직 미결인 신고 수."""
    query = db.session.query(func.count(Report.id)).join(
        User, Report.reporter_id == User.id
    ).filter(
        User.status == "active",
        Report.status == "pending",
    )
    if product_id is not None:
        query = query.filter(Report.reported_product_id == product_id)
    else:
        query = query.filter(Report.reported_user_id == user_id)
    return query.scalar() or 0


def _mark_pending_auto_actioned(*, product_id=None, user_id=None) -> None:
    q = Report.query.filter(Report.status == "pending")
    if product_id is not None:
        q = q.filter(Report.reported_product_id == product_id)
    else:
        q = q.filter(Report.reported_user_id == user_id)
    q.update({"status": "auto_actioned"}, synchronize_session=False)


def _ensure_active_reporter(reporter: User) -> None:
    if reporter is None or reporter.status != "active":
        raise ValidationError("활성 상태의 사용자만 신고할 수 있습니다.")


def _duplicate_exists(*, reporter_id, product_id=None, user_id=None) -> bool:
    query = Report.query.filter(Report.reporter_id == reporter_id)
    if product_id is not None:
        query = query.filter(Report.reported_product_id == product_id)
    else:
        query = query.filter(Report.reported_user_id == user_id)
    return query.first() is not None


def report_product(reporter: User, product_id: str, reason: str) -> Report:
    _ensure_active_reporter(reporter)
    reason = validate_reason(reason)
    product = _visible_product(product_id)
    if product is None:
        raise NotFound()
    if product.seller_id == reporter.id:
        raise ValidationError("본인 상품은 신고할 수 없습니다.")

    report = Report(
        reporter_id=reporter.id, reported_product_id=product.id, reason=reason
    )
    try:
        db.session.add(report)
        db.session.flush()  # UNIQUE(reporter, product) 및 이번 행 집계 반영
        write_audit(
            "user", "report_product", actor_id=reporter.id, target=product.id
        )

        # 조건부 UPDATE의 영향 행수로 동시 요청에서도 자동조치·감사를 1회만 기록한다.
        count = _active_report_count(product_id=product.id)
        if count >= current_app.config["REPORT_BLOCK_THRESHOLD"]:
            changed = Product.query.filter(
                Product.id == product.id,
                Product.status == "active",
            ).update(
                {"status": "blocked"},
                synchronize_session="fetch",
            )
            if changed == 1:
                _mark_pending_auto_actioned(product_id=product.id)
                write_audit(
                    "system",
                    "product_auto_block",
                    target=product.id,
                    detail=f"{count} active pending reports",
                )
        db.session.commit()
        return report
    except IntegrityError:
        db.session.rollback()
        if _duplicate_exists(
            reporter_id=reporter.id,
            product_id=product.id,
        ):
            raise ValidationError("이미 신고한 상품입니다.")
        raise
    except Exception:
        db.session.rollback()
        raise


def report_user(reporter: User, user_id: str, reason: str) -> Report:
    _ensure_active_reporter(reporter)
    reason = validate_reason(reason)
    target = db.session.get(User, user_id)
    if target is None or target.status != "active":
        raise NotFound()
    if target.role != "user":
        # 일반 신고 흐름으로 관리자 계정을 자동 휴면시키는 권한 상승을 막는다.
        raise NotFound()
    if target.id == reporter.id:
        raise ValidationError("본인은 신고할 수 없습니다.")

    report = Report(
        reporter_id=reporter.id, reported_user_id=target.id, reason=reason
    )
    try:
        db.session.add(report)
        db.session.flush()  # UNIQUE(reporter, user)·자기신고 CHECK 반영
        write_audit(
            "user", "report_user", actor_id=reporter.id, target=target.id
        )

        count = _active_report_count(user_id=target.id)
        if count >= current_app.config["REPORT_USER_DORMANT_THRESHOLD"]:
            changed = User.query.filter(
                User.id == target.id,
                User.status == "active",
                User.role == "user",
            ).update(
                {"status": "dormant"},
                synchronize_session="fetch",
            )
            if changed == 1:
                _mark_pending_auto_actioned(user_id=target.id)
                write_audit(
                    "system",
                    "user_auto_dormant",
                    target=target.id,
                    detail=f"{count} active pending reports",
                )
        db.session.commit()
        return report
    except IntegrityError:
        db.session.rollback()
        if _duplicate_exists(
            reporter_id=reporter.id,
            user_id=target.id,
        ):
            raise ValidationError("이미 신고한 사용자입니다.")
        raise
    except Exception:
        db.session.rollback()
        raise
