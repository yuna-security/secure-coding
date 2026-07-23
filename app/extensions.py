"""Flask 확장 인스턴스 (팩토리에서 init_app)."""
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import CSRFProtect
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO

db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()
login_manager = LoginManager()

# HTTP 라우트 Rate Limiting (Socket.IO는 별도 계층에서 처리 — 설계 §3)
limiter = Limiter(key_func=get_remote_address, default_limits=[])

# 동일 출처만 허용(팩토리에서 None으로 설정). cors_allowed_origins는 init_app에서 지정.
socketio = SocketIO()

login_manager.login_view = "auth.login"
login_manager.login_message = "로그인이 필요합니다."
login_manager.session_protection = "strong"
