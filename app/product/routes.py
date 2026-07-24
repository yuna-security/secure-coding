"""상품 라우트 (P4): 등록/목록/상세/검색/내 상품/수정/삭제 + 이미지 서빙.

공개(익명): 목록·상세·검색·이미지.  로그인: 등록·수정·삭제·내 상품(⑩).
소유자만 수정·삭제(⑪, IDOR).
"""
from flask import (
    Blueprint, render_template, redirect, url_for, flash, request,
    current_app, send_from_directory, abort,
)
from flask_login import login_required, current_user

from ..extensions import db
from ..models import User
from ..auth.service import ValidationError
from . import service
from .forms import ProductForm, DeleteForm
from ..report import reporter_rate_limit, report_ip_rate_limit
from ..report.forms import ReportForm
from ..report import service as report_service

product_bp = Blueprint("product", __name__)


def _render_detail(product_id, report_form=None, status=200):
    product = service.get_product_detail_or_404(product_id, current_user)
    seller = db.session.get(User, product.seller_id)
    is_owner = current_user.is_authenticated and current_user.id == product.seller_id
    can_report = current_user.is_authenticated and not is_owner
    return render_template(
        "product/detail.html",
        product=product,
        seller=seller,
        is_owner=is_owner,
        can_report=can_report,
        delete_form=DeleteForm(),
        report_form=report_form or ReportForm(),
    ), status


# ---------- 공개 조회 ----------

@product_bp.route("/products")
def list_():
    page = request.args.get("page", 1, type=int)
    if page < 1:
        page = 1
    try:
        q = service.clean_search_query(request.args.get("q"))
    except ValidationError:
        abort(400)
    sort = service.normalize_sort(request.args.get("sort", "newest"))
    pagination = service.list_products(page, q=q, sort=sort)
    return render_template(
        "product/list.html", pagination=pagination, q=q, sort=sort, search=False
    )


@product_bp.route("/products/search")
def search():
    page = request.args.get("page", 1, type=int)
    if page < 1:
        page = 1
    try:
        q = service.clean_search_query(request.args.get("q"))
    except ValidationError:
        abort(400)
    sort = service.normalize_sort(request.args.get("sort", "newest"))
    pagination = service.list_products(page, q=q, sort=sort)
    return render_template(
        "product/list.html", pagination=pagination, q=q, sort=sort, search=True
    )


@product_bp.route("/products/<product_id>")
def detail(product_id):
    return _render_detail(product_id)


@product_bp.route("/products/<product_id>/report", methods=["POST"])
@login_required
@reporter_rate_limit
@report_ip_rate_limit
def report(product_id):
    form = ReportForm()
    if form.validate_on_submit():
        try:
            report_service.report_product(
                current_user._get_current_object(), product_id, form.reason.data
            )
        except ValidationError as exc:
            flash(str(exc))
            return _render_detail(product_id, report_form=form, status=400)
        flash("신고가 접수되었습니다.")
        return redirect(url_for("product.list_"))
    return _render_detail(product_id, report_form=form, status=400)


@product_bp.route("/uploads/<filename>")
def uploaded_file(filename):
    service.authorize_image_or_404(filename, current_user)
    response = send_from_directory(
        current_app.config["UPLOAD_FOLDER"], filename, max_age=0
    )
    # 차단·휴면 전환 직후에도 공유 캐시에서 이미지가 계속 노출되지 않게 한다.
    response.headers["Cache-Control"] = "private, no-store"
    return response


# ---------- 등록/관리(로그인) ----------

@product_bp.route("/products/new", methods=["GET", "POST"])
@login_required
def new():
    form = ProductForm()
    if form.validate_on_submit():
        try:
            product = service.create_product(
                current_user._get_current_object(),
                form.title.data,
                form.description.data,
                form.price.data,
                form.image.data,
            )
        except ValidationError as exc:
            flash(str(exc))
            return render_template("product/new.html", form=form), 400
        flash("상품이 등록되었습니다.")
        return redirect(url_for("product.detail", product_id=product.id))
    status = 400 if request.method == "POST" else 200
    return render_template("product/new.html", form=form), status


@product_bp.route("/me/products")
@login_required
def mine():
    products = service.own_products(current_user.id)
    return render_template("product/mine.html", products=products, delete_form=DeleteForm())


@product_bp.route("/products/<product_id>/edit", methods=["GET", "POST"])
@login_required
def edit(product_id):
    product = service.get_owned_product_or_error(product_id, current_user)
    form = ProductForm(obj=product)
    if request.method == "GET":
        form.price.data = str(product.price)
    if form.validate_on_submit():
        try:
            service.update_product(
                product,
                form.title.data,
                form.description.data,
                form.price.data,
                form.image.data,
            )
        except ValidationError as exc:
            flash(str(exc))
            return render_template("product/edit.html", form=form, product=product), 400
        flash("상품이 수정되었습니다.")
        return redirect(url_for("product.detail", product_id=product.id))
    status = 400 if request.method == "POST" else 200
    return render_template("product/edit.html", form=form, product=product), status


@product_bp.route("/products/<product_id>/delete", methods=["POST"])
@login_required
def delete(product_id):
    product = service.get_owned_product_or_error(product_id, current_user)
    form = DeleteForm()
    if not form.validate_on_submit():
        abort(400)
    service.soft_delete(product, current_user._get_current_object())
    flash("상품이 삭제되었습니다.")
    return redirect(url_for("product.mine"))
