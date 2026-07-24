# P10 배포·운영 증적 (HTTPS/WSS·파일 권한·README 재현)

> 설계 §10의 P10 단계. 로컬에서 수집 가능한 증적은 자동 캡처했고, 실제 기기·POSIX
> 배포가 필요한 증적은 재현 가능한 런북으로 남긴다. 체크리스트 매핑은
> [`CHECKLIST_VERIFICATION.ko.md`](CHECKLIST_VERIFICATION.ko.md) 참고.

## 1. HTTPS / TLS 실증 (㉕·④·㉔) — 로컬 자체서명으로 캡처 완료

`prod` 설정으로 자체서명 TLS 위에서 구동해 수집. 원문:
[`evidence/P10_HTTPS_TLS.txt`](evidence/P10_HTTPS_TLS.txt).

- HTTPS `GET /` → 200, `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- 보안 헤더: CSP·`X-Frame-Options: DENY`·`X-Content-Type-Options: nosniff` 존재
- 회원가입 POST 302(`/login`) / 로그인 POST 302(`/`)(성공) — HTTPS에서 Flask-WTF가
  **Referer 동일 출처**를 추가 강제(CSRF 강화)
- 세션 쿠키 `Secure=True HttpOnly=True SameSite=Lax`
- 인증 페이지 `GET /wallet` 200 — 로그인 세션이 TLS 위에서 정상 동작

## 2. WSS (⑰) — 실제 WebSocket 연결·왕복 완료

Werkzeug에 인증서를 직접 건 첫 시도는 `write() before start_response`로 실패했다.
실제 운영 구조와 같은 **TLS 종료 역방향 프록시 → loopback 앱** 구성으로 다시 검증해,
`wss://`에서 WebSocket 전송을 강제한 인증 사용자의 연결과 메시지 왕복에 성공했다.
원문: [`evidence/P10_WSS.txt`](evidence/P10_WSS.txt).

- 앱의 WebSocket 자체(연결 인증·발신자 결정·DM 격리·Rate Limit)는 `tests/test_p5_chat.py`(32건)와
  P5 개발 브라우저 실시간 왕복으로 검증 완료.
- 프록시 전달 헤더는 기본적으로 신뢰하지 않고, `TRUST_PROXY_HEADERS=1`일 때 한 단계만
  신뢰한다(`tests/test_p10_operations.py`).
- 실제 WSS 증적: `ENGINEIO_TRANSPORT=websocket`, 인증된 서버측 발신자,
  `P10 WSS encrypted round trip` 송수신, `WSS_RESULT=PASS`.
- 따라서 공식 체크리스트 ⑰은 **✅ 완료**다. ngrok·핸드폰 화면은 제출 보고서의
  시각 자료를 강화하는 선택적 추가 증적으로 남긴다.

## 3. DB·업로드 파일 권한 (㉓) — Windows 실증·POSIX 자동 적용

`app/security.py`가 연결된 SQLite 파일에 `0600`, `app/__init__.py`가 `instance/`·
`uploads/`에 `0700`을 적용한다(`set_private_mode`). Windows는 chmod 권한 모델이 달라
no-op이며(코드가 분기 처리), 로직은 `tests/test_p9_checklist.py::
test_posix_private_modes_are_applied_to_sqlite_and_instance`로 검증한다.

POSIX(Linux/macOS) 배포에서 아래로 실제 권한 증적을 남긴다:

```bash
APP_ENV=prod SECRET_KEY=... flask --app app db upgrade
python app.py &                 # 최초 요청 1회로 uploads/instance 생성·권한 적용
ls -l instance/market.db        # -rw------- (0600)
ls -ld instance instance/uploads  # drwx------ (0700)
```

현재 Windows 환경에서는 적용 전 ACL에 `Authenticated Users:(M)`과
`BUILTIN\Users:(RX)`가 있음을 발견했다. 상속을 제거하고 현재 앱 실행 사용자·SYSTEM·
Administrators만 허용한 뒤 `icacls`로 재검증했다. 원문:
[`evidence/P10_WINDOWS_ACL.txt`](evidence/P10_WINDOWS_ACL.txt).

## 4. 핸드폰·HTTPS/WSS 실사용 런북 (사용자 실행)

ngrok 계정과 실제 단말이 필요한 단계다. 순서:

```bash
# 1) .env 설정 — 앱은 loopback 유지
APP_ENV=prod
HOST=127.0.0.1
PORT=5000
TRUST_PROXY_HEADERS=1
SECRET_KEY=<충분히 긴 무작위 값>

# 2) 앱 실행
python app.py

# 3) 별도 터미널에서 TLS 터널
ngrok http 5000
```

수집할 증적:
- 발급된 `https://<id>.ngrok-free.app` 접속 → 브라우저 주소창 자물쇠(유효 TLS)
- 로그인 후 개발자도구 Network에서 `wss://<id>.ngrok-free.app/socket.io/...` 업그레이드 확인
- 전체 채팅·DM 실시간 왕복, XSS 페이로드가 텍스트로 렌더링됨
- 응답 헤더 `Strict-Transport-Security` 존재, 세션 쿠키 `Secure`
- 테스트 종료 후 `.env`의 `APP_ENV=dev`, `TRUST_PROXY_HEADERS=0` 복구

> `TRUST_PROXY_HEADERS=1`은 loopback 또는 방화벽으로 보호되어 앱 포트에 프록시만
> 접근할 수 있을 때만 사용한다. 직접 공개 포트에서 켜면 전달 헤더를 위조할 수 있다.

## 5. README 재현 검증 (완료)

새 Python 3.13 가상환경과 깨끗한 임시 DB로 README 절차를 처음부터 실행해 확인. 원문:
[`evidence/P10_README_REPRODUCTION.txt`](evidence/P10_README_REPRODUCTION.txt).
pip 26.1.2·requirements 설치 → `db upgrade`(head 도달) → `create-admin` →
`python app.py`(GET / , /products 200) → `pytest -q`(253 passed).

## 6. 요약

| 항목 | 상태 |
|------|------|
| ㉕ HTTPS·HSTS·Secure 쿠키 | ✅ 로컬 TLS로 캡처(`evidence/P10_HTTPS_TLS.txt`) |
| ⑰ WSS | ✅ TLS 종료 프록시에서 실제 WebSocket 연결·인증 메시지 왕복 완료(`evidence/P10_WSS.txt`) |
| ㉓ 파일 권한 | ✅ Windows ACL 최소화·실증 완료, POSIX 0600/0700 코드·단위검증 |
| README 재현 | ✅ 새 venv·임시 DB에서 전체 재현 완료(`evidence/P10_README_REPRODUCTION.txt`) |
