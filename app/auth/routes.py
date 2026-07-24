"""인증 라우트 (회원가입/로그인/로그아웃/비밀번호 변경).

P2 공통 기반 범위. 프로필 조회·소개글 수정 등 확장 R1 기능은 P3에서 추가.
"""
from flask import Blueprint, render_template, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user

from ..extensions import db, limiter
from ..models import write_audit
from . import service
from .forms import RegisterForm, LoginForm, LogoutForm, ChangePasswordForm

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            service.register_user(form.username.data, form.password.data)
        except service.ValidationError as exc:
            flash(str(exc))
            return render_template("auth/register.html", form=form), 400
        flash("회원가입이 완료되었습니다. 로그인 해주세요.")
        return redirect(url_for("auth.login"))
    return render_template("auth/register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])  # IP 단위 (⑥, 계정 잠금과 병행)
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    form = LoginForm()
    if form.validate_on_submit():
        result, user = service.attempt_login(form.username.data, form.password.data)
        if result == service.LoginResult.OK:
            write_audit("user", "login", actor_id=user.id)
            db.session.commit()
            login_user(user, fresh=True)
            session.permanent = True
            flash("로그인 성공!")
            return redirect(url_for("main.index"))
        if result == service.LoginResult.LOCKED:
            flash("로그인 시도가 많아 계정이 일시 잠겼습니다. 잠시 후 다시 시도하세요.")
        elif result == service.LoginResult.DORMANT:
            flash("휴면 상태 계정입니다. 관리자에게 문의하세요.")
        else:
            flash("아이디 또는 비밀번호가 올바르지 않습니다.")
        return render_template("auth/login.html", form=form), 401
    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    form = LogoutForm()
    if form.validate_on_submit():
        user_id = current_user.id
        write_audit("user", "logout", actor_id=user_id)
        db.session.commit()
        logout_user()
        # 페이지가 닫히지 않은 별도 탭/클라이언트의 기존 소켓도 서버에서 폐기한다.
        from ..chat.connections import disconnect_user_sockets

        disconnect_user_sockets(user_id)
        flash("로그아웃되었습니다.")
    return redirect(url_for("main.index"))


@auth_bp.route("/me/password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user = current_user._get_current_object()
        try:
            service.change_password(
                user, form.current_password.data, form.new_password.data
            )
        except service.ValidationError as exc:
            flash(str(exc))
            return render_template("auth/change_password.html", form=form), 400
        write_audit("user", "password_change", actor_id=user.id)
        db.session.commit()
        from ..chat.connections import disconnect_user_sockets

        disconnect_user_sockets(user.id)
        # 민감정보 변경 후 기존 세션 상태를 버리고 fresh 세션으로 재발급한다.
        session.clear()
        login_user(user, fresh=True)
        session.permanent = True
        flash("비밀번호가 변경되었습니다.")
        return redirect(url_for("main.index"))
    return render_template("auth/change_password.html", form=form)
