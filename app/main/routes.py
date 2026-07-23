"""공개(익명 접근 가능) 라우트 — 랜딩/헬스체크.

상품 목록·상세·검색(익명 조회)은 P4에서 product 블루프린트로 확장.
"""
from flask import Blueprint, render_template, jsonify

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/healthz")
def healthz():
    return jsonify(status="ok")
