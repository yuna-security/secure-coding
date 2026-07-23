"""인증 서비스: 비밀번호 해시/검증, 입력 검증, 로그인 시도 제한.

- Argon2id 해시 (V-02, 체크리스트 ③)
- 서버측 입력 검증 (V-06, ①)
- 로그인 실패 잠금 (V-09, ⑥) — 계정 단위. IP 단위 제한은 라우트의 Flask-Limiter가 담당.
"""
import re
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash
from flask import current_app
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import User, utcnow_naive

_ph = PasswordHasher()
_DUMMY_HASH = _ph.hash("constant-time-user-enumeration-guard")

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_]+$")


class ValidationError(Exception):
    pass


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False


def validate_username(username: str) -> str:
    username = (username or "").strip()
    lo = current_app.config["USERNAME_MIN"]
    hi = current_app.config["USERNAME_MAX"]
    if not (lo <= len(username) <= hi):
        raise ValidationError(f"사용자명은 {lo}~{hi}자여야 합니다.")
    if not _USERNAME_RE.match(username):
        raise ValidationError("사용자명은 영문/숫자/밑줄(_)만 사용할 수 있습니다.")
    return username


def validate_password(password: str) -> str:
    password = password or ""
    lo = current_app.config["PASSWORD_MIN"]
    hi = current_app.config["PASSWORD_MAX"]
    if not (lo <= len(password) <= hi):
        raise ValidationError(f"비밀번호는 {lo}~{hi}자여야 합니다.")
    return password


def register_user(username: str, password: str) -> User:
    username = validate_username(username)
    validate_password(password)
    if User.query.filter_by(username=username).first() is not None:
        raise ValidationError("이미 존재하는 사용자명입니다.")
    user = User(username=username, password_hash=hash_password(password))
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError as exc:
        # 사전 조회 이후 동시에 같은 사용자명이 생성되는 경쟁조건도 안전하게 처리한다.
        db.session.rollback()
        raise ValidationError("이미 존재하는 사용자명입니다.") from exc
    return user


def _is_locked(user: User) -> bool:
    return user.locked_until is not None and user.locked_until > utcnow_naive()


class LoginResult:
    OK = "ok"
    BAD_CREDENTIALS = "bad_credentials"
    LOCKED = "locked"
    DORMANT = "dormant"


def attempt_login(username: str, password: str):
    """(결과코드, user|None) 반환. 사용자 열거 방지를 위해 실패 메시지는 동일하게 처리."""
    username = (username or "").strip()
    user = User.query.filter_by(username=username).first()

    if user is None:
        # 존재하지 않는 계정도 Argon2 검증 비용을 지불해 타이밍 기반 열거를 완화한다.
        verify_password(_DUMMY_HASH, password)
        return LoginResult.BAD_CREDENTIALS, None

    if _is_locked(user):
        return LoginResult.LOCKED, None

    if not verify_password(user.password_hash, password):
        user.failed_login_count += 1
        if user.failed_login_count >= current_app.config["LOGIN_MAX_FAILURES"]:
            user.locked_until = utcnow_naive() + timedelta(
                minutes=current_app.config["LOGIN_LOCK_MINUTES"]
            )
            user.failed_login_count = 0
        db.session.commit()
        return LoginResult.BAD_CREDENTIALS, None

    # 인증 성공
    if user.status == "dormant":
        return LoginResult.DORMANT, None

    user.failed_login_count = 0
    user.locked_until = None
    if _ph.check_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    return LoginResult.OK, user


def change_password(user: User, current_password: str, new_password: str):
    """민감 작업: 현재 비밀번호 재확인 후 변경 (⑤ 재인증)."""
    if not verify_password(user.password_hash, current_password):
        raise ValidationError("현재 비밀번호가 올바르지 않습니다.")
    validate_password(new_password)
    user.password_hash = hash_password(new_password)
