"""운영 WSGI 진입점.

운영에서는 반드시 APP_ENV=prod + SECRET_KEY 환경변수 + HTTPS/WSS 역방향
프록시를 사용하고, WebSocket을 지원하는 WSGI 서버가 ``wsgi:app``을 로드한다.
구체적인 배포 명령은 최종 README에서 고정한다.
"""
import os

from dotenv import load_dotenv

load_dotenv()

from app import create_app  # noqa: E402
from app.extensions import socketio  # noqa: E402

app = create_app(os.environ.get("APP_ENV", "prod"))

__all__ = ["app", "socketio"]
