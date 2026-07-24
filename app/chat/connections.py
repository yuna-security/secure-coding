"""인증 사용자별 Socket.IO 연결 추적.

로그아웃·휴면 전환 뒤 이미 연결된 소켓이 전체 채팅이나 DM을 계속 수신하지 않도록
사용자 ID와 Socket.IO sid를 연결한다. 과제의 단일 프로세스 실행 기준 인메모리
레지스트리이며, 다중 워커 운영 시에는 Socket.IO message queue와 공유 저장소로
교체해야 한다.
"""
import threading
from collections import defaultdict

from flask import current_app

from ..extensions import socketio


_lock = threading.Lock()
_sids_by_user = defaultdict(set)
_user_by_sid = {}


def remember_connection(user_id: str, sid: str) -> None:
    with _lock:
        previous = _user_by_sid.get(sid)
        if previous is not None and previous != user_id:
            _sids_by_user[previous].discard(sid)
        _user_by_sid[sid] = user_id
        _sids_by_user[user_id].add(sid)


def forget_connection(sid: str) -> None:
    with _lock:
        user_id = _user_by_sid.pop(sid, None)
        if user_id is None:
            return
        bucket = _sids_by_user.get(user_id)
        if bucket is None:
            return
        bucket.discard(sid)
        if not bucket:
            _sids_by_user.pop(user_id, None)


def disconnect_user_sockets(user_id: str) -> int:
    """사용자의 현재 소켓을 모두 서버에서 종료하고 종료 개수를 반환한다."""
    with _lock:
        sids = tuple(_sids_by_user.pop(user_id, ()))
        for sid in sids:
            _user_by_sid.pop(sid, None)

    disconnected = 0
    for sid in sids:
        try:
            socketio.server.disconnect(sid, namespace="/")
            disconnected += 1
        except Exception:
            # DB 상태 변경은 이미 commit된 뒤다. 연결 정리 실패가 상태 트랜잭션의
            # 성공을 거짓 실패로 바꾸지 않게 하며, 다음 이벤트의 _actor 재검증도 남는다.
            current_app.logger.warning(
                "Failed to disconnect stale chat socket user_id=%s", user_id
            )
            continue
    return disconnected


def reset_connections() -> None:
    """테스트 격리용."""
    with _lock:
        _sids_by_user.clear()
        _user_by_sid.clear()
