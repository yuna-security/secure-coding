"""개발용 실행 진입점.

    python app.py

애플리케이션 팩토리는 `app/` 패키지에 있으며, 이 파일은 개발 서버 실행만 담당한다.
운영 배포는 `wsgi.py`(HTTPS/WSS 프록시 뒤)에서 구동한다.
"""
import os

from dotenv import load_dotenv

load_dotenv()  # .env 로드(있으면)

from app import create_app  # noqa: E402  (load_dotenv 이후 import)
from app.extensions import socketio  # noqa: E402

application = create_app(os.environ.get("APP_ENV", "dev"))

if __name__ == "__main__":
    # 기본은 loopback으로만 연다. 핸드폰/ngrok 테스트 때만 HOST=0.0.0.0을 명시한다.
    # 모든 환경에서 대화형 디버거는 비활성화한다(V-04).
    socketio.run(
        application,
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
        # Flask-SocketIO의 개발 서버 사용 확인. 운영은 wsgi.py를 WSGI 서버에서 로드한다.
        allow_unsafe_werkzeug=True,
    )
