"""신고 폼 (Flask-WTF) — CSRF 포함(②). 설정값 단일 출처."""
from flask import current_app
from flask_wtf import FlaskForm
from wtforms import TextAreaField, SubmitField
from wtforms.validators import DataRequired, ValidationError


class ReportForm(FlaskForm):
    reason = TextAreaField(
        "신고 사유", validators=[DataRequired(message="신고 사유를 입력하세요.")]
    )
    submit = SubmitField("신고")

    def validate_reason(self, field):
        value = (field.data or "").strip()
        if not value:
            raise ValidationError("신고 사유를 입력하세요.")
        limit = current_app.config["REPORT_REASON_MAX"]
        if len(value) > limit:
            raise ValidationError(f"신고 사유는 최대 {limit}자까지 입력할 수 있습니다.")
