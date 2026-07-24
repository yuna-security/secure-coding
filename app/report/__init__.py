"""신고 기능 공통 Rate Limit.

상품·사용자 신고 라우트가 같은 한도를 공유한다. 인증 사용자와 IP를
각각 제한해 계정 전환 및 단일 계정의 다중 대상 스팸을 함께 완화한다.
"""
from flask import current_app
from flask_login import current_user
from flask_limiter.util import get_remote_address

from ..extensions import limiter


def _reporter_key():
    return current_user.get_id() or f"anonymous:{get_remote_address()}"


reporter_rate_limit = limiter.shared_limit(
    lambda: current_app.config["REPORT_USER_RATE_LIMIT"],
    scope="report-submission-by-user",
    key_func=_reporter_key,
    methods=["POST"],
)

report_ip_rate_limit = limiter.shared_limit(
    lambda: current_app.config["REPORT_IP_RATE_LIMIT"],
    scope="report-submission-by-ip",
    key_func=get_remote_address,
    methods=["POST"],
)
