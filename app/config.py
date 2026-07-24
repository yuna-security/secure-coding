"""환경별 설정 클래스 (dev / test / prod).

- 비밀키는 환경변수에서 로드(운영은 필수). (V-01)
- 세션 쿠키 보안 속성. (V-11, 체크리스트 ④)
- 업로드 최대 크기. (V-18, 이미지 5MB)
"""
import os
import secrets
from datetime import timedelta

try:  # StaticPool는 인메모리 테스트 DB 공유에 필요
    from sqlalchemy.pool import StaticPool
except Exception:  # pragma: no cover
    StaticPool = None


class BaseConfig:
    # 핵심 보안
    SECRET_KEY = None

    # DB
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///market.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # 세션 쿠키 (④ 세션 쿠키 설정)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False  # 로컬 HTTP 기본값, 운영에서 True
    SESSION_COOKIE_NAME = "secure_coding_session"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)  # ⑤ 세션 만료

    # CSRF (②)
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # 세션 수명에 종속

    # 업로드 (⑧/V-18): 요청 본문 상한 5MB
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024

    # Rate limit 저장소 (HTTP; Flask-Limiter)
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_HEADERS_ENABLED = True

    # python-engineio에서 None이 요청 Host 기준 동일 출처 검증을 의미한다. (⑭)
    SOCKET_ALLOWED_ORIGINS = None

    # 도메인 상수
    LOGIN_MAX_FAILURES = 5          # ⑥ 실패 로그인 방어
    LOGIN_LOCK_MINUTES = 10
    USERNAME_MIN = 3
    USERNAME_MAX = 20
    PASSWORD_MIN = 8
    PASSWORD_MAX = 128
    BIO_MAX = 500
    REPORT_REASON_MAX = 1000
    CHAT_MESSAGE_MAX = 500
    REPORT_BLOCK_THRESHOLD = 3          # 상품 자동 차단 임계치 (AC4.3)
    REPORT_USER_DORMANT_THRESHOLD = 3   # 사용자 자동 휴면 임계치 (AC4.4)
    REPORT_USER_RATE_LIMIT = "30 per hour"  # 상품·사용자 신고 합산(인증 사용자)
    REPORT_IP_RATE_LIMIT = "100 per hour"   # 다계정·자동화 신고 보조 제한

    # 관리자(R7)
    ADMIN_PAGE_SIZE = 30            # 관리자 목록 페이지네이션(사용자/상품/신고/로그)

    # 상품 (R2) / 검색 (R6)
    PRODUCT_TITLE_MAX = 120         # 모델 String(120)과 일치
    PRODUCT_DESC_MAX = 4000         # 모델 String(4000)과 일치
    PRICE_MIN = 1                   # ⑧ 가격 범위
    PRICE_MAX = 1_000_000_000
    PRODUCTS_PER_PAGE = 20          # AC2.5 페이지네이션
    SEARCH_QUERY_MAX = 100
    # 정렬 허용목록(SQLi 방지 — 동적 정렬값 화이트리스트) (㉒, AC6.2)
    PRODUCT_SORT_OPTIONS = ("newest", "price_asc", "price_desc")

    # 이미지 업로드 (V-18, AC2.3)
    UPLOAD_FOLDER = None            # 팩토리에서 instance_path/uploads로 확정
    ALLOWED_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
    ALLOWED_IMAGE_FORMATS = {"JPEG", "PNG", "WEBP"}  # Pillow 판정 포맷
    IMAGE_EXT_BY_FORMAT = {"JPEG": ".jpg", "PNG": ".png", "WEBP": ".webp"}
    IMAGE_MIME_BY_FORMAT = {
        "JPEG": {"image/jpeg"},
        "PNG": {"image/png"},
        "WEBP": {"image/webp"},
    }
    MAX_IMAGE_DIMENSION = 4096      # 픽셀(가로/세로 상한, 압축폭탄 방지)
    MAX_IMAGE_PIXELS = 4096 * 4096  # 전체 디코딩 픽셀 상한


class DevConfig(BaseConfig):
    # 디버거 콘솔 노출(V-04)을 막기 위해 개발 기본값도 False로 유지한다.
    DEBUG = False
    # 환경변수가 없으면 프로세스마다 예측 불가 임시 키를 생성한다.
    # 재시작 후 세션 유지가 필요하면 .env에 SECRET_KEY를 설정한다.
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_urlsafe(32)


class TestConfig(BaseConfig):
    TESTING = True
    SECRET_KEY = "test-key"
    SQLALCHEMY_DATABASE_URI = "sqlite://"  # 인메모리
    WTF_CSRF_ENABLED = False  # 기능 테스트 단순화(CSRF 자체는 전용 테스트에서 검증)
    RATELIMIT_ENABLED = False
    if StaticPool is not None:
        # 단일 인메모리 연결 공유(스레드 간 데이터 유지)
        SQLALCHEMY_ENGINE_OPTIONS = {
            "connect_args": {"check_same_thread": False},
            "poolclass": StaticPool,
        }


class ProdConfig(BaseConfig):
    DEBUG = False
    SESSION_COOKIE_SECURE = True  # HTTPS 필수 (㉕)

    @classmethod
    def validate(cls, config):
        if not config.get("SECRET_KEY"):
            raise RuntimeError("운영 환경에서는 SECRET_KEY 환경변수가 반드시 필요합니다.")


CONFIG_MAP = {"dev": DevConfig, "test": TestConfig, "prod": ProdConfig}
