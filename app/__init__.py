"""애플리케이션 팩토리.

보안 공통 기반(P2): 설정 분리, ORM, 인증(세션/CSRF/로그인 잠금), 보안 헤더,
안전한 오류 처리, Rate Limiting, 감사 로그 토대.
"""
import os

from flask import Flask
from flask_login import current_user

from .config import CONFIG_MAP
from .extensions import db, migrate, csrf, login_manager, limiter, socketio
from . import models
from .security import register_security


def create_app(config_name=None):
    config_name = config_name or os.environ.get("APP_ENV", "dev")
    if config_name not in CONFIG_MAP:
        raise RuntimeError(
            f"알 수 없는 APP_ENV={config_name!r}. dev, test, prod 중 하나를 사용하세요."
        )
    config_class = CONFIG_MAP[config_name]

    app = Flask(__name__)
    app.config.from_object(config_class)
    # 설정 모듈 import 이후 환경변수가 주입된 경우에도 최신 값을 사용한다.
    if config_name != "test" and os.environ.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
    if hasattr(config_class, "validate"):
        config_class.validate(app.config)

    # 확장 초기화
    db.init_app(app)
    migrate.init_app(app, db, compare_type=True, render_as_batch=True)
    csrf.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    socketio.init_app(
        app, cors_allowed_origins=app.config.get("SOCKET_ALLOWED_ORIGINS")
    )

    @login_manager.user_loader
    def load_user(user_id):
        user = db.session.get(models.User, user_id)
        # 휴면 전환된 기존 세션도 다음 요청부터 즉시 무효화한다.
        return user if user is not None and user.is_active else None

    # 업로드 폴더 확정(instance 하위, 실행 불가·정적 서빙 대상 아님) + 생성
    upload_folder = app.config.get("UPLOAD_FOLDER") or os.path.join(
        app.instance_path, "uploads"
    )
    app.config["UPLOAD_FOLDER"] = os.path.abspath(upload_folder)
    # 테스트는 fixture가 격리된 임시 폴더를 주입하므로 기본 경로를 만들지 않는다.
    if not app.testing:
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        if os.name != "nt":
            try:
                os.chmod(app.config["UPLOAD_FOLDER"], 0o700)
            except OSError:
                pass  # POSIX 권한 변경을 지원하지 않는 파일시스템

    # 보안 헤더 + 오류 처리
    register_security(app)

    # 블루프린트
    from .main.routes import main_bp
    from .auth.routes import auth_bp
    from .user.routes import user_bp
    from .product.routes import product_bp
    from .admin.routes import admin_bp
    from .chat.routes import chat_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(product_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(chat_bp)

    # Socket.IO 이벤트 핸들러 등록(전체/DM 채팅 — R3).
    from .chat.events import register_chat_events

    register_chat_events(socketio)

    # CLI
    from .cli import register_cli

    register_cli(app)

    # 템플릿 공통 컨텍스트
    @app.context_processor
    def inject_user():
        return {"current_user": current_user}

    return app
