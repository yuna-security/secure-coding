Exit code: 0
Wall time: 0.6 seconds
Output:
# P0 — 스타터 런타임 재현 & before 증적

> 작성: 2026-07-23, Claude (Fable 5)
> 대상: 멘토 스타터 baseline `f0dd4baac057f62315bb4850f05d18b7e60eb4be`
> 환경: 로컬 전용 실행(Windows, venv: flask 3.1.3 + flask-socketio + python-socketio client). **ngrok/외부 공개 없이** 127.0.0.1에서만 재현.
> 목적: `docs/STARTER_SECURITY_AUDIT.ko.md`의 정적 분석 결과 중 핵심 취약점을 **실제 실행으로 실증**(개선 전 상태). 개선 후(after)와 대조하기 위한 증적.

---

## 증적 1 — 비밀번호 평문 저장 (V-02) 🔴

- 절차: `POST /register` (username=`victim`, password=`SuperSecret!234`) → 로그인 → `market.db` 직접 조회
- 결과:
  ```
  [user] username='victim'
         password (평문 그대로 저장됨!) = 'SuperSecret!234'
  ```
- 해석: 입력한 비밀번호가 해시/솔트 없이 DB `user.password`에 원문 그대로 저장됨. DB 유출 시 전 계정 즉시 탈취. → P2에서 bcrypt/Argon2 적용 후 동일 절차로 해시값 저장 확인(after).

## 증적 2 — 입력 검증 부재: 가격 임의값·길이 무제한·스크립트 원문 저장 (V-06, V-14, V-15) 🟠

- 절차: 로그인 세션으로 `POST /product/new` (price=`공짜; DROP? -1`, title=`"A"*500`, description=`<script>alert(1)</script>`)
- 결과(DB 저장값):
  ```
  [product] price (숫자검증 없음, TEXT 그대로) = '공짜; DROP? -1'
            title 길이 = 500자 (길이 제한 없음)
            description = '<script>alert(1)</script>' (원문 저장; 렌더는 Jinja autoescape에만 의존)
  ```
- 해석: 가격이 숫자·범위 검증 없이 임의 문자열로 저장(`price TEXT`), 제목 길이 무제한, 스크립트 문자열이 그대로 DB에 저장됨. 현재는 Jinja 자동 이스케이프로 출력 시 XSS가 막히지만 서버측 sanitize·검증은 전무(심층 방어 없음). → P4에서 서버측 검증(숫자·범위·길이) 후 거부되는지 확인(after).

## 증적 3 — `debug=True` 대화형 디버거·스택트레이스 노출 (V-04, V-16) 🔴

- 절차: `POST /register` 에 폼 필드 누락 → 예외 발생
- 결과: **HTTP 500**, 응답 본문에 Werkzeug 디버거가 그대로 노출:
  ```
  werkzeug.exceptions.BadRequestKeyError: 400 Bad Request ...
  KeyError: 'username'
  // Werkzeug Debugger
      var CONSOLE_MODE = false,
          EVALEX = true,            <-- 대화형 코드 실행 콘솔 활성
          EVALEX_TRUSTED = false,
          SECRET = "Qb6iIPVtYudIa8zQfoFl";
  Traceback (most recent call last)
    File "...\.venv\Lib\site-packages\flask\app.py", line 1536, in __call__ ...
  ```
- 해석: `EVALEX=true`(대화형 파이썬 콘솔) + 전체 스택트레이스 + 서버 파일 경로가 공격자에게 노출. 디버거 PIN 우회 시 **원격 코드 실행**으로 이어질 수 있는 최악의 운영 설정. → P2에서 `debug=False` + 커스텀 에러 핸들러 적용 후, 동일 요청이 일반 오류 페이지(내부정보 미노출)로 응답하는지 확인(after).

## 증적 4 — Socket.IO 비인증 연결 + 발신자 username 위조 (V-05) 🟠

- 절차: **로그인 세션 없이** python-socketio 클라이언트로 연결 후 `send_message` emit (username=`관리자(사칭)`)
- 결과:
  ```
  비인증 상태로 Socket 연결 성공: True
  서버가 위조 username을 그대로 브로드캐스트:
    [{'username': '관리자(사칭)', 'message': '나는 아무나 사칭할 수 있다', 'message_id': 'a41c1a19-...'}]
  ```
- 해석: (1) 로그인하지 않아도 소켓 연결·발화 가능, (2) 서버가 발신자 신원을 검증하지 않고 **클라이언트가 보낸 username을 그대로 신뢰·전파** → 누구나 임의 사용자(관리자 포함) 사칭. → P5에서 연결 시 세션 인증 + 서버 세션에서 발신자 결정 후, 위조 시도가 거부/무시되는지 확인(after).

---

## 재현 방법(요약)

```bash
# 스타터 baseline clone 후
python -m venv .venv && .venv/Scripts/pip install flask flask-socketio requests "python-socketio[client]" websocket-client
python app.py            # 127.0.0.1:5000, 로컬 전용 (debug=True 주의: 외부 공개 금지)
python collect_evidence.py    # 증적 1,2
python collect_evidence2.py   # 증적 3,4
```

> 주의: `debug=True` 서버는 대화형 디버거가 열려 있어 **절대 ngrok 등으로 외부에 공개하지 않는다.**
