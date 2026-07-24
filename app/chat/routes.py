"""채팅 HTTP 라우트 (P5, R3).

- GET /chat            전체 실시간 채팅 화면 + 최근 히스토리 (로그인)
- GET /chat/dm/<uid>   1:1 DM 화면 (로그인 + 대상 active·비본인) — 방을 생성/조회 후
                       참여자만 접근(§7). 방 id는 서버가 발급, 소켓 이벤트에서 재검증.
"""
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user

from ..auth.service import ValidationError
from . import service

chat_bp = Blueprint("chat", __name__)


@chat_bp.route("/chat")
@login_required
def global_chat():
    messages = service.recent_global()
    return render_template("chat/global.html", messages=messages)


@chat_bp.route("/chat/dm/<user_id>")
@login_required
def dm(user_id):
    me = current_user._get_current_object()
    try:
        room = service.get_or_create_dm_room(me, user_id)
    except ValidationError as exc:
        flash(str(exc))
        return redirect(url_for("chat.global_chat"))
    other = service.get_active_user_or_404(user_id)
    messages = service.dm_history(room)
    return render_template(
        "chat/dm.html", room=room, other=other, messages=messages
    )
