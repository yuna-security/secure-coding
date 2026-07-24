"""Socket.IO 이벤트용 사용자 ID 기반 Rate Limiter (⑯, 설계 §3).

Flask-Limiter는 HTTP 라우트만 보호하고 Socket.IO 이벤트를 자동 제한하지 않으므로,
사용자 ID를 키로 하는 슬라이딩 윈도우 카운터를 별도로 둔다. 단일 프로세스(dev/과제)
기준 인메모리 구현이며, 다중 워커 운영 시에는 공유 저장소(예: Redis) 기반으로 교체한다.
"""
import threading
import time
from collections import defaultdict, deque

from flask import current_app


class SlidingWindowLimiter:
    def __init__(self):
        self._events = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, max_events: int, window: float) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._events[key]
            cutoff = now - window
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= max_events:
                return False
            bucket.append(now)
            return True

    def reset(self):
        with self._lock:
            self._events.clear()


chat_limiter = SlidingWindowLimiter()


def chat_rate_ok(user_id: str, event: str = "message") -> bool:
    cfg = current_app.config
    return chat_limiter.allow(
        f"chat:{event}:{user_id}",
        cfg["CHAT_RATE_MAX_EVENTS"],
        cfg["CHAT_RATE_WINDOW_SECONDS"],
    )
