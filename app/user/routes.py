"""사용자 프로필 라우트 (P3).

- F1.3 사용자 조회: GET /users/<id> (로그인 필요, 민감정보 제외 — SR-02)
- F1.4 소개글 수정: GET/POST /me (본인만, 서버측 검증 + CSRF)
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user

from ..extensions import db
from ..models import write_audit
from ..auth.service import ValidationError
from . import service
from .forms import ProfileForm
from ..report import reporter_rate_limit, report_ip_rate_limit
from ..report.forms import ReportForm
from ..report import service as report_service

user_bp = Blueprint("user", __name__)


@user_bp.route("/me", methods=["GET", "POST"])
@login_required
def me():
    user = current_user._get_current_object()
    form = ProfileForm(obj=user)
    if form.validate_on_submit():
        try:
            service.update_bio(user, form.bio.data)
        except ValidationError as exc:
            flash(str(exc))
            return render_template("user/me.html", form=form, user=user), 400
        write_audit("user", "update_bio", actor_id=user.id)
        db.session.commit()
        flash("프로필이 저장되었습니다.")
        return redirect(url_for("user.me"))
    status = 400 if request.method == "POST" and form.errors else 200
    return render_template("user/me.html", form=form, user=user), status


def _render_profile(user_id, report_form=None, status=200):
    user = service.get_user_or_404(user_id)
    profile = service.public_profile(user)
    is_me = user.id == current_user.id
    can_report = (
        (not is_me)
        and user.status == "active"
        and user.role == "user"
    )
    return render_template(
        "user/profile.html",
        profile=profile,
        is_me=is_me,
        target_id=user.id,
        can_report=can_report,
        report_form=report_form or ReportForm(),
    ), status


@user_bp.route("/users/<user_id>")
@login_required
def profile(user_id):
    return _render_profile(user_id)


@user_bp.route("/users/<user_id>/report", methods=["POST"])
@login_required
@reporter_rate_limit
@report_ip_rate_limit
def report(user_id):
    form = ReportForm()
    if form.validate_on_submit():
        try:
            report_service.report_user(
                current_user._get_current_object(), user_id, form.reason.data
            )
        except ValidationError as exc:
            flash(str(exc))
            return _render_profile(user_id, report_form=form, status=400)
        flash("신고가 접수되었습니다.")
        return redirect(url_for("user.profile", user_id=user_id))
    return _render_profile(user_id, report_form=form, status=400)
