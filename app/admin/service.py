"""관리자 서비스 (P8, R7) — 상태 관리·신고 검토·읽기 전용 열람.

핵심 안전 원칙 (트랜잭션 경합 방어):
- 모든 상태 변경은 **조건부 UPDATE + 영향행수==1 검증**으로 가드한다.
  동시 관리자 조치·신고 자동조치와 경합해도 이중 적용/무성공 없이 정확히 1회만
  적용되며, 기대 상태가 아니면 409(Conflict)로 실패한다(P6 자동조치와 동일 패턴).
- 각 조치는 단일 트랜잭션(변경→감사→commit), 예외 시 rollback.
- 관리자 감사(actor_type='admin', actor_id=관리자)로 부인 방지(SR-05).

권한/무결성 경계:
- 관리자 계정은 휴면 대상이 아니다(권한 상승·상호 잠금 방지).
- 잔액 직접 수정 경로 없음(AC7.5). 지급(grant)은 원장 트랜잭션이 필요하므로 P7로 이월.
- 목록 열람은 비밀번호 해시·잔액 등 민감정보를 노출하지 않는다(§7, AC7.5).
"""
from functools import wraps

from flask import current_app
from werkzeug.exceptions import NotFound, Conflict, Forbidden

from ..extensions import db
from ..models import (
    User, Product, Report, AuditLog, Transfer, write_audit, utcnow_naive,
)
from ..auth.service import ValidationError

RESOLUTIONS = ("upheld", "reversed", "dismissed")
REPORT_STATUSES = ("pending", "auto_actioned", "reviewed", "resolved")


def _transactional(operation):
    """관리자 역할을 재검증하고 모든 예외에서 변경·감사를 rollback한다."""
    @wraps(operation)
    def wrapped(admin, *args, **kwargs):
        try:
            actor_id = getattr(admin, "id", None)
            actor = db.session.get(User, actor_id) if actor_id else None
            if actor is None:
                raise Forbidden()
            # 현재 DB 값을 다시 읽어 stale 세션 객체를 통한 권한 우회를 막는다.
            db.session.refresh(actor)
            if actor.role != "admin" or actor.status != "active":
                raise Forbidden()
            return operation(actor, *args, **kwargs)
        except Exception:
            db.session.rollback()
            raise

    return wrapped


def _has_auto_actioned_reports(*, user_id=None, product_id=None) -> bool:
    query = Report.query.filter(Report.status == "auto_actioned")
    if product_id is not None:
        query = query.filter(Report.reported_product_id == product_id)
    else:
        query = query.filter(Report.reported_user_id == user_id)
    return query.first() is not None


# ---------- 사용자 상태 (AC7.2) ----------

@_transactional
def set_user_dormant(admin: User, user_id: str) -> None:
    target = db.session.get(User, user_id)
    if target is None:
        raise NotFound()
    if target.role != "user":
        # 관리자 계정은 휴면 대상이 아니다(권한 상승·상호 잠금 차단).
        raise ValidationError("관리자 계정은 휴면 대상이 아닙니다.")
    changed = User.query.filter(
        User.id == user_id, User.status == "active", User.role == "user"
    ).update({"status": "dormant"}, synchronize_session=False)
    if changed != 1:
        raise Conflict()
    write_audit("admin", "admin_user_dormant", actor_id=admin.id, target=user_id)
    db.session.commit()


@_transactional
def restore_user(admin: User, user_id: str) -> None:
    target = db.session.get(User, user_id)
    if target is None:
        raise NotFound()
    if target.role != "user":
        raise ValidationError("관리자 계정은 복구 대상이 아닙니다.")
    if _has_auto_actioned_reports(user_id=user_id):
        # 자동조치는 신고 결정(reversed)을 통해서만 복구한다.
        raise Conflict()
    changed = User.query.filter(
        User.id == user_id,
        User.status == "dormant",
        User.role == "user",
    ).update({"status": "active"}, synchronize_session=False)
    if changed != 1:
        raise Conflict()
    write_audit("admin", "admin_user_restore", actor_id=admin.id, target=user_id)
    db.session.commit()


# ---------- 상품 상태 (AC7.3) ----------

@_transactional
def block_product(admin: User, product_id: str) -> None:
    product = db.session.get(Product, product_id)
    if product is None:
        raise NotFound()
    changed = Product.query.filter(
        Product.id == product_id, Product.status == "active"
    ).update({"status": "blocked"}, synchronize_session=False)
    if changed != 1:
        raise Conflict()
    write_audit("admin", "admin_product_block", actor_id=admin.id, target=product_id)
    db.session.commit()


@_transactional
def restore_product(admin: User, product_id: str) -> None:
    product = db.session.get(Product, product_id)
    if product is None:
        raise NotFound()
    if _has_auto_actioned_reports(product_id=product_id):
        # 자동 차단을 일반 복구 라우트로 우회하지 못하게 한다.
        raise Conflict()
    # blocked 또는 (soft) deleted → active 복구 (§6 상태전이).
    changed = Product.query.filter(
        Product.id == product_id, Product.status.in_(("blocked", "deleted"))
    ).update({"status": "active"}, synchronize_session=False)
    if changed != 1:
        raise Conflict()
    write_audit("admin", "admin_product_restore", actor_id=admin.id, target=product_id)
    db.session.commit()


@_transactional
def delete_product(admin: User, product_id: str) -> None:
    product = db.session.get(Product, product_id)
    if product is None:
        raise NotFound()
    # active·blocked → deleted(soft). 이미 deleted면 경합/무변경으로 409.
    changed = Product.query.filter(
        Product.id == product_id, Product.status.in_(("active", "blocked"))
    ).update({"status": "deleted"}, synchronize_session=False)
    if changed != 1:
        raise Conflict()
    write_audit("admin", "admin_product_delete", actor_id=admin.id, target=product_id)
    db.session.commit()


# ---------- 신고 검토·결정 (AC7.4 / §6) ----------

@_transactional
def review_report(admin: User, report_id: str) -> None:
    """pending → reviewed. 자동조치(auto_actioned) 건은 곧바로 resolve로 처리."""
    report = db.session.get(Report, report_id)
    if report is None:
        raise NotFound()
    changed = Report.query.filter(
        Report.id == report_id, Report.status == "pending"
    ).update(
        {
            "status": "reviewed",
            "reviewed_by": admin.id,
            "reviewed_at": utcnow_naive(),
        },
        synchronize_session=False,
    )
    if changed != 1:
        raise Conflict()
    write_audit("admin", "admin_report_review", actor_id=admin.id, target=report_id)
    db.session.commit()


@_transactional
def resolve_report(admin: User, report_id: str, resolution: str) -> None:
    """검토/자동조치 상태의 신고를 최종 결정한다.

    - reviewed      → upheld | dismissed (대상 상태 변경 없음)
    - auto_actioned → upheld | reversed  (같은 대상의 자동조치 묶음을 일괄 결정)
    `reversed`는 대상 복구를 가드된 조건부 UPDATE로 수행한다. 자동 차단 뒤 별도로
    삭제된 상품은 이후 조치를 존중해 삭제 상태를 유지한다.
    """
    if resolution not in RESOLUTIONS:
        raise ValidationError("올바르지 않은 결정입니다.")
    report = db.session.get(Report, report_id)
    if report is None:
        raise NotFound()

    source = report.status
    if source == "auto_actioned":
        if resolution not in ("upheld", "reversed"):
            raise ValidationError("자동 조치 신고는 유지 또는 복구만 가능합니다.")
    elif source == "reviewed":
        if resolution not in ("upheld", "dismissed"):
            raise ValidationError("검토 완료 신고는 유지 또는 기각만 가능합니다.")
    else:
        # pending·resolved 등은 직접 결정 대상이 아니다.
        raise Conflict()

    reviewed_at = utcnow_naive()
    values = {
        "status": "resolved",
        "resolution": resolution,
        "reviewed_by": admin.id,
        "reviewed_at": reviewed_at,
    }

    # 선택한 행을 먼저 조건부 갱신해 동시 관리자 중 정확히 한 명만 처리권을 얻는다.
    selected = Report.query.filter(
        Report.id == report_id,
        Report.status == source,
    ).update(values, synchronize_session=False)
    if selected != 1:
        raise Conflict()

    affected = 1
    if source == "auto_actioned":
        _validate_auto_action_target(report)
        # 같은 자동조치로 전이된 대상별 신고는 서로 다른 결론이 생기지 않게
        # 한 트랜잭션에서 동일 resolution으로 일괄 종결한다.
        cohort = Report.query.filter(
            Report.status == "auto_actioned",
            Report.id != report_id,
        )
        if report.reported_product_id is not None:
            cohort = cohort.filter(
                Report.reported_product_id == report.reported_product_id
            )
        else:
            cohort = cohort.filter(
                Report.reported_user_id == report.reported_user_id
            )
        affected += cohort.update(values, synchronize_session=False)

        if resolution == "reversed":
            _restore_report_target(admin, report)

    write_audit(
        "admin", "admin_report_resolve",
        actor_id=admin.id,
        target=report_id,
        detail=f"{resolution}; cohort={affected}",
    )
    db.session.commit()


def _validate_auto_action_target(report: Report) -> None:
    """자동조치가 일반 복구로 우회되지 않았는지 대상 상태를 확인한다."""
    if report.reported_product_id is not None:
        product = db.session.get(Product, report.reported_product_id)
        if product is None or product.status not in ("blocked", "deleted"):
            raise Conflict()
    else:
        target = db.session.get(User, report.reported_user_id)
        if (
            target is None
            or target.role != "user"
            or target.status != "dormant"
        ):
            raise Conflict()


def _restore_report_target(admin: User, report: Report) -> None:
    """reversed 결정 시 자동조치 대상을 복구한다.

    차단 뒤 소유자/관리자가 삭제한 상품은 이후 조치를 존중해 deleted로 유지한다.
    """
    if report.reported_product_id is not None:
        changed = Product.query.filter(
            Product.id == report.reported_product_id, Product.status == "blocked"
        ).update({"status": "active"}, synchronize_session=False)
        if changed == 1:
            write_audit(
                "admin", "admin_product_restore",
                actor_id=admin.id, target=report.reported_product_id,
                detail="report reversed",
            )
    elif report.reported_user_id is not None:
        changed = User.query.filter(
            User.id == report.reported_user_id,
            User.status == "dormant",
            User.role == "user",
        ).update({"status": "active"}, synchronize_session=False)
        if changed == 1:
            write_audit(
                "admin", "admin_user_restore",
                actor_id=admin.id, target=report.reported_user_id,
                detail="report reversed",
            )


# ---------- 읽기 전용 열람 (AC7.5) ----------

def _page_size():
    return current_app.config["ADMIN_PAGE_SIZE"]


def list_users(page: int):
    return User.query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=_page_size(), error_out=False
    )


def list_products(page: int):
    return Product.query.order_by(Product.created_at.desc()).paginate(
        page=page, per_page=_page_size(), error_out=False
    )


def list_reports(page: int, status: str = None):
    query = Report.query.order_by(Report.created_at.desc())
    if status in REPORT_STATUSES:
        query = query.filter(Report.status == status)
    return query.paginate(page=page, per_page=_page_size(), error_out=False)


def list_audit_logs(page: int):
    return AuditLog.query.order_by(AuditLog.created_at.desc()).paginate(
        page=page, per_page=_page_size(), error_out=False
    )


def list_transactions(page: int):
    # 불변 원장 열람(감사). balance 직접 노출 없음. P7 송금 구현 전에는 비어 있다.
    return Transfer.query.order_by(Transfer.created_at.desc()).paginate(
        page=page, per_page=_page_size(), error_out=False
    )


def dashboard_stats() -> dict:
    def _by_status(model):
        rows = (
            db.session.query(model.status, db.func.count(model.id))
            .group_by(model.status)
            .all()
        )
        return {status: count for status, count in rows}

    return {
        "users": _by_status(User),
        "products": _by_status(Product),
        "reports": _by_status(Report),
        "audit_count": db.session.query(db.func.count(AuditLog.id)).scalar() or 0,
    }
