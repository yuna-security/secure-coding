"""프로필 폼 (Flask-WTF) — CSRF 포함(②)."""
from flask import current_app
from flask_wtf import FlaskForm
from wtforms import TextAreaField, SubmitField
from wtforms.validators import ValidationError


class ProfileForm(FlaskForm):
    bio = TextAreaField("소개글")
    submit = SubmitField("저장")

    def validate_bio(self, field):
        limit = current_app.config["BIO_MAX"]
        if len(field.data or "") > limit:
            raise ValidationError(f"소개글은 최대 {limit}자까지 입력할 수 있습니다.")
