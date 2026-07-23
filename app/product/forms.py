"""상품 폼 (Flask-WTF) — CSRF 포함(②). 설정값 단일 출처(current_app.config)."""
from flask import current_app
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField, SubmitField
from wtforms.validators import DataRequired, ValidationError


class ProductForm(FlaskForm):
    title = StringField("상품명", validators=[DataRequired(message="상품명을 입력하세요.")])
    description = TextAreaField("설명")
    price = StringField("가격(원)", validators=[DataRequired(message="가격을 입력하세요.")])
    image = FileField("사진(선택: jpg/png/webp)")
    submit = SubmitField("저장")

    def validate_title(self, field):
        value = (field.data or "").strip()
        if not value:
            raise ValidationError("상품명을 입력하세요.")
        limit = current_app.config["PRODUCT_TITLE_MAX"]
        if len(value) > limit:
            raise ValidationError(f"상품명은 최대 {limit}자까지 입력할 수 있습니다.")

    def validate_description(self, field):
        limit = current_app.config["PRODUCT_DESC_MAX"]
        if len(field.data or "") > limit:
            raise ValidationError(f"설명은 최대 {limit}자까지 입력할 수 있습니다.")

    def validate_price(self, field):
        raw = (field.data or "").strip()
        if not raw.isdigit():  # 음수·소수·문자 전부 거부(⑧)
            raise ValidationError("가격은 0보다 큰 정수여야 합니다.")
        price = int(raw)
        lo = current_app.config["PRICE_MIN"]
        hi = current_app.config["PRICE_MAX"]
        if not (lo <= price <= hi):
            raise ValidationError(f"가격은 {lo}~{hi:,}원 범위여야 합니다.")

    def validate_image(self, field):
        # 확장자 1차 검증(딥 검증은 서비스의 Pillow 재인코딩에서 수행 — V-18)
        data = field.data
        if data and getattr(data, "filename", ""):
            ext = data.filename.rsplit(".", 1)[-1].lower() if "." in data.filename else ""
            if ext not in current_app.config["ALLOWED_IMAGE_EXTENSIONS"]:
                raise ValidationError("허용되지 않은 이미지 형식입니다(jpg/png/webp).")


class DeleteForm(FlaskForm):
    """삭제 전용(CSRF 토큰 확보용)."""
    submit = SubmitField("삭제")
