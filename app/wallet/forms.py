"""지갑·송금 폼 (Flask-WTF) — CSRF 포함(②)."""
from flask_wtf import FlaskForm
from wtforms import StringField, HiddenField, SubmitField
from wtforms.validators import DataRequired


class TransferForm(FlaskForm):
    recipient = StringField(
        "받는 사람(사용자명)", validators=[DataRequired(message="받는 사람을 입력하세요.")]
    )
    amount = StringField(
        "금액", validators=[DataRequired(message="금액을 입력하세요.")]
    )
    memo = StringField("메모")
    # 재전송·더블클릭에도 동일 결과가 되도록 서버가 발급한 멱등 키를 폼에 싣는다(AC5.4).
    idempotency_key = HiddenField()
    submit = SubmitField("송금")
