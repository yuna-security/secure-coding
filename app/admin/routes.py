"""관리자 라우트 (P8, R7).

- AC7.1 RBAC: 전 라우트 @admin_required.
- 상태 변경은 조회(GET)와 분리한 개별 POST 엔드포인트 + CSRF + 감사(§4).
- 응답 계약: 성공→목록으로 redirect(302)+flash, 입력/규칙 위반→400,
  경합/불가 상태 전이→409(서비스가 raise), 미존재→404.
"""
from flask import (
    Blueprint, render_template, redirect, url_for, flash, request, abort,
)
from flask_login import current_user

from . import admin_required
from . import service as admin_service
from .forms import AdminActionForm, ResolveReportForm
from ..auth.service import ValidationError

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def _page():
    page = request.args.get("page", 1, type=int)
    return page if page and page >= 1 else 1


def _me():
    return current_user._get_current_object()


# ---------- 조회 ----------

@admin_bp.route("")
@admin_required
def dashboard():
    return render_template(
        "admin/dashboard.html", stats=admin_service.dashboard_stats()
    )


@admin_bp.route("/users")
@admin_required
def users():
    return render_template(
        "admin/users.html",
        pagination=admin_service.list_users(_page()),
        action_form=AdminActionForm(),
    )


@admin_bp.route("/products")
@admin_required
def products():
    return render_template(
        "admin/products.html",
        pagination=admin_service.list_products(_page()),
        action_form=AdminActionForm(),
    )


@admin_bp.route("/reports")
@admin_required
def reports():
    status = request.args.get("status") or None
    return render_template(
        "admin/reports.html",
        pagination=admin_service.list_reports(_page(), status=status),
        status=status,
        action_form=AdminActionForm(),
        resolve_form=ResolveReportForm(),
    )


@admin_bp.route("/logs")
@admin_required
def logs():
    return render_template(
        "admin/logs.html", pagination=admin_service.list_audit_logs(_page())
    )


@admin_bp.route("/transactions")
@admin_required
def transactions():
    return render_template(
        "admin/transactions.html",
        pagination=admin_service.list_transactions(_page()),
    )


# ---------- 상태 변경(POST) ----------

def _require_action_form():
    if not AdminActionForm().validate_on_submit():
        abort(400)


@admin_bp.route("/users/<user_id>/dormant", methods=["POST"])
@admin_required
def user_dormant(user_id):
    _require_action_form()
    try:
        admin_service.set_user_dormant(_me(), user_id)
    except ValidationError:
        abort(400)
    flash("사용자를 휴면 처리했습니다.")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<user_id>/restore", methods=["POST"])
@admin_required
def user_restore(user_id):
    _require_action_form()
    try:
        admin_service.restore_user(_me(), user_id)
    except ValidationError:
        abort(400)
    flash("사용자를 복구했습니다.")
    return redirect(url_for("admin.users"))


@admin_bp.route("/products/<product_id>/block", methods=["POST"])
@admin_required
def product_block(product_id):
    _require_action_form()
    try:
        admin_service.block_product(_me(), product_id)
    except ValidationError:
        abort(400)
    flash("상품을 차단했습니다.")
    return redirect(url_for("admin.products"))


@admin_bp.route("/products/<product_id>/restore", methods=["POST"])
@admin_required
def product_restore(product_id):
    _require_action_form()
    try:
        admin_service.restore_product(_me(), product_id)
    except ValidationError:
        abort(400)
    flash("상품을 복구했습니다.")
    return redirect(url_for("admin.products"))


@admin_bp.route("/products/<product_id>/delete", methods=["POST"])
@admin_required
def product_delete(product_id):
    _require_action_form()
    try:
        admin_service.delete_product(_me(), product_id)
    except ValidationError:
        abort(400)
    flash("상품을 삭제했습니다.")
    return redirect(url_for("admin.products"))


@admin_bp.route("/reports/<report_id>/review", methods=["POST"])
@admin_required
def report_review(report_id):
    _require_action_form()
    try:
        admin_service.review_report(_me(), report_id)
    except ValidationError:
        abort(400)
    flash("신고를 검토 상태로 표시했습니다.")
    return redirect(url_for("admin.reports"))


@admin_bp.route("/reports/<report_id>/resolve", methods=["POST"])
@admin_required
def report_resolve(report_id):
    form = ResolveReportForm()
    if not form.validate_on_submit():
        abort(400)
    try:
        admin_service.resolve_report(_me(), report_id, form.resolution.data)
    except ValidationError:
        abort(400)
    flash("신고를 처리했습니다.")
    return redirect(url_for("admin.reports"))
