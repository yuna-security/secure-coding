"""관리자(R7) 공통 — RBAC 데코레이터.

- AC7.1 `role=admin`만 관리자 라우트 접근(SR-02).
- 미인증은 로그인 요구(login_required와 동일 흐름), 인증되었으나 비관리자는 403.
"""
from functools import wraps

from flask import abort
from flask_login import login_required, current_user


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        # 여기 도달했다면 login_required를 통과(인증됨). 역할만 추가 확인한다.
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)

    return wrapped
