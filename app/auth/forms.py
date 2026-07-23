"""인증 폼 (Flask-WTF) — CSRF 토큰 자동 포함(②)."""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length


class RegisterForm(FlaskForm):
    username = StringField("사용자명", validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField("비밀번호", validators=[DataRequired(), Length(min=8, max=128)])
    submit = SubmitField("회원가입")


class LoginForm(FlaskForm):
    username = StringField("사용자명", validators=[DataRequired(), Length(max=20)])
    password = PasswordField("비밀번호", validators=[DataRequired(), Length(max=128)])
    submit = SubmitField("로그인")


class LogoutForm(FlaskForm):
    submit = SubmitField("로그아웃")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("현재 비밀번호", validators=[DataRequired()])
    new_password = PasswordField(
        "새 비밀번호", validators=[DataRequired(), Length(min=8, max=128)]
    )
    submit = SubmitField("비밀번호 변경")
