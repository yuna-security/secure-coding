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


@user_bp.route("/users/<user_id>")
@login_required
def profile(user_id):
    user = service.get_user_or_404(user_id)
    profile = service.public_profile(user)
    is_me = user.id == current_user.id
    return render_template("user/profile.html", profile=profile, is_me=is_me)
