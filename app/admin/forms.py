"""관리자 폼 (Flask-WTF) — 모든 상태 변경 POST에 CSRF 토큰(②) 강제."""
from flask_wtf import FlaskForm
from wtforms import SubmitField, SelectField
from wtforms.validators import DataRequired

from .service import RESOLUTIONS


class AdminActionForm(FlaskForm):
    """추가 입력이 없는 상태 변경(휴면/복구/차단/삭제/검토)용 — CSRF 전용."""
    submit = SubmitField("실행")


class ResolveReportForm(FlaskForm):
    resolution = SelectField(
        "결정",
        choices=[(r, r) for r in RESOLUTIONS],
        validators=[DataRequired()],
    )
    submit = SubmitField("결정")
