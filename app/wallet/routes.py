"""지갑·송금 라우트 (P7, R5).

- GET  /wallet           잔액 + 본인 거래 내역(AC5.5, 본인만 — IDOR 방지)
- POST /wallet/transfer  송금(로그인 + CSRF + Rate Limit). 원자적·멱등(SR-03).

응답 계약: 성공→/wallet redirect(302)+flash, 입력/규칙 위반→400(폼 재렌더),
멱등 충돌(같은 키·다른 파라미터)→409(서비스가 raise).
"""
import uuid

from flask import (
    Blueprint, render_template, redirect, url_for, flash, request, current_app,
    abort,
)
from flask_login import login_required, current_user

from ..extensions import limiter
from ..auth.service import ValidationError
from . import service
from .forms import TransferForm

wallet_bp = Blueprint("wallet", __name__)


def _require_user():
    if current_user.role != "user":
        abort(403)


def _page():
    page = request.args.get("page", 1, type=int)
    return page if page and page >= 1 else 1


def _render_wallet(form, status=200):
    me = current_user._get_current_object()
    return render_template(
        "wallet/index.html",
        balance=service.get_balance(me),
        pagination=service.transaction_history(me.id, _page()),
        me_id=me.id,
        form=form,
    ), status


@wallet_bp.route("/wallet")
@login_required
def index():
    _require_user()
    form = TransferForm()
    # 새 멱등 키 발급(GET마다) — 제출 시 재전송이 같은 키를 재사용해 멱등 보장.
    form.idempotency_key.data = uuid.uuid4().hex
    prefill = request.args.get("to")
    if prefill:
        form.recipient.data = prefill
    return _render_wallet(form)


@wallet_bp.route("/wallet/transfer", methods=["POST"])
@login_required
@limiter.limit(lambda: current_app.config["TRANSFER_RATE_LIMIT"], methods=["POST"])
@limiter.limit(
    lambda: current_app.config["TRANSFER_USER_RATE_LIMIT"],
    key_func=lambda: current_user.get_id() or "anonymous",
    methods=["POST"],
)
def transfer():
    _require_user()
    form = TransferForm()
    if not form.validate_on_submit():
        return _render_wallet(form, status=400)
    try:
        service.transfer_points(
            current_user._get_current_object(),
            form.recipient.data,
            form.amount.data,
            form.memo.data,
            form.idempotency_key.data,
        )
    except ValidationError as exc:
        flash(str(exc))
        # 실패한 요청은 새 키로 재시도하도록 키를 재발급한다.
        form.idempotency_key.data = uuid.uuid4().hex
        return _render_wallet(form, status=400)
    flash("송금이 완료되었습니다.")
    return redirect(url_for("wallet.index"))
