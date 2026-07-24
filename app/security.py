"""보안 헤더 + 안전한 오류 처리 (V-04, V-12, V-16 / 체크리스트 ⑦㉔㉖).

- 응답 보안 헤더 일괄 적용
- 예외/오류 시 스택트레이스·내부정보 미노출(일반 오류 페이지)
"""
from flask import render_template, request
from flask_login import current_user
from sqlalchemy import event
from sqlalchemy.engine import Engine

# SQLite 외래키 강제(연결마다 PRAGMA). CHECK/FK 무결성 보장.
@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):  # pragma: no cover
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
    except Exception:
        # 비-SQLite 엔진이면 무시
        pass


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self'; "
        "script-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    ),
}


def register_security(app):
    def _log_sanitized_exception(exc_info):
        # Flask 기본 로거는 예외 메시지와 traceback 전체를 남기므로 안전한 형태로 대체한다.
        error_type = type(exc_info[1]).__name__ if exc_info and exc_info[1] else "Unknown"
        app.logger.error(
            "Unhandled request exception method=%s path=%s type=%s",
            request.method,
            request.path,
            error_type,
        )

    app.log_exception = _log_sanitized_exception

    @app.after_request
    def _apply_security_headers(response):
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        # 인증·계정 화면이 브라우저/공유 프록시 캐시에 남지 않게 한다.
        if current_user.is_authenticated or request.blueprint == "auth":
            response.headers.setdefault("Cache-Control", "no-store")
        # HSTS는 운영(HTTPS)에서만
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response

    def _render_error(status, message):
        try:
            return render_template("errors/error.html", status=status, message=message), status
        except Exception:  # 템플릿 로드 실패 시에도 내부정보 노출 금지
            return message, status

    @app.errorhandler(400)
    def _bad_request(e):
        return _render_error(400, "잘못된 요청입니다.")

    @app.errorhandler(403)
    def _forbidden(e):
        return _render_error(403, "접근 권한이 없습니다.")

    @app.errorhandler(404)
    def _not_found(e):
        return _render_error(404, "페이지를 찾을 수 없습니다.")

    @app.errorhandler(413)
    def _too_large(e):
        return _render_error(413, "업로드 용량이 너무 큽니다.")

    @app.errorhandler(409)
    def _conflict(e):
        # 동시 상태 변경 등 경합으로 조건부 UPDATE가 적용되지 못한 경우.
        return _render_error(409, "이미 처리되었거나 상태가 변경되어 요청을 완료할 수 없습니다.")

    @app.errorhandler(429)
    def _rate_limited(e):
        return _render_error(429, "요청이 너무 많습니다. 잠시 후 다시 시도하세요.")

    @app.errorhandler(500)
    def _server_error(e):
        # 실제 예외는 위의 정제된 로거가 유형만 기록한다.
        return _render_error(500, "서버 오류가 발생했습니다.")
