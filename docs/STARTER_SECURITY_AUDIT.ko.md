Exit code: 0
Wall time: 0.6 seconds
Output:
# P0 — 멘토 스타터 보안 감사 보고서

> 작성: 2026-07-23, Claude (Fable 5)
> 런타임 실증 증적: `docs/BASELINE_RUNTIME_EVIDENCE.ko.md` (V-02 평문 비밀번호, V-04 debug 디버거, V-05 Socket 발신자 위조, V-06/14/15 입력검증 부재를 실제 실행으로 확인)
> 대상 저장소: https://github.com/ugonfor/secure-coding
> **기준 커밋(baseline)**: `f0dd4baac057f62315bb4850f05d18b7e60eb4be` — "Add helloworld.py" (2025-03-22 17:35:44 +0900)
> 감사 방식: 전체 소스 정적 분석 (app.py, templates/*.html 9개, secure_coding_checklist.csv, enviroments.yaml, readme.md, helloworld.py)
> 감사 범위: 이 보고서는 "개선 전(before)" 상태의 증적이다. 각 항목은 P2~P9에서 수정하고 after 증적과 연결한다.

---

## 0. 스타터 구성 요약

- 스택: Python 3.9, Flask, Flask-SocketIO, **raw `sqlite3`** (enviroments.yaml에는 flask-sqlalchemy가 있으나 코드에서 미사용)
- 단일 파일 `app.py`(210줄) + Jinja2 템플릿 9개
- DB 테이블 3개: `user(id, username, password, bio)`, `product(id, title, description, price, seller_id)`, `report(id, reporter_id, target_id, reason)`
- 구현된 기능: 회원가입, 로그인/로그아웃, 대시보드(상품목록+전체채팅), 프로필(소개글), 상품 등록/상세, 신고 접수, Socket.IO 전체 브로드캐스트 채팅
- 미구현(슬라이드 29쪽 빨간 글씨 + 과제 요구): 사용자 조회, 비밀번호 변경, 내 상품 수정·삭제, 1:1 채팅, 불량 상품 삭제, 불량 유저 휴면, **송금·검색·관리자 전체**

---

## 1. 취약점 목록 (심각도순)

심각도: 🔴 Critical / 🟠 High / 🟡 Medium / 🔵 Low

### 🔴 V-01. 하드코딩된 SECRET_KEY (`app.py:7`)
```python
app.config['SECRET_KEY'] = 'secret!'
```
- 세션 쿠키 서명 키가 소스에 노출·고정. 공격자가 임의 세션(예: 타 사용자·관리자) 위조 가능.
- **개선**: 환경변수/`.env`에서 로드, 없으면 기동 실패 또는 안전한 난수 생성. 저장소에는 비포함.

### 🔴 V-02. 비밀번호 평문 저장 및 평문 비교 (`app.py:81-82, 96`)
```python
cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)", (user_id, username, password))
...
cursor.execute("SELECT * FROM user WHERE username = ? AND password = ?", (username, password))
```
- DB 유출 시 전 계정 비밀번호 즉시 노출. 로그인도 평문 대조.
- **개선**: bcrypt/Argon2 + 고유 salt 해시 저장, 로그인 시 해시 검증(`check_password_hash`). (체크리스트 "비밀번호 보안")

### 🔴 V-03. CSRF 보호 전무 (모든 폼: register/login/profile/new_product/report)
- 어떤 폼에도 CSRF 토큰 없음. 로그인 상태 피해자를 유도해 상품 등록·신고·프로필 변경 등 상태변경 요청을 위조 가능.
- **개선**: Flask-WTF `CSRFProtect` 전역 적용, 모든 POST 폼에 토큰, Socket 이벤트도 인증 검증. (체크리스트 "CSRF 보호")

### 🔴 V-04. `debug=True` 운영 노출 (`app.py:210`)
```python
socketio.run(app, debug=True)
```
- Werkzeug 대화형 디버거 → 예외 발생 시 스택 트레이스 노출 및 **원격 코드 실행(PIN 우회 시)** 위험.
- **개선**: 운영에서 `debug=False`, 환경변수로 개발/운영 분리, 커스텀 에러 핸들러. (체크리스트 "오류 메시지", "에러 및 예외 처리")

### 🟠 V-05. Socket.IO 채팅 인증 부재 + 발신자 신원 위조 가능 (`app.py:203-206`, `dashboard.html`)
```python
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)
```
```js
socket.emit('send_message', { 'username': "{{ user.username }}", 'message': message });
```
- 서버가 발신자를 **클라이언트가 보낸 `username`** 그대로 신뢰 → 누구나 임의 사용자명 사칭 가능.
- 연결 시 로그인 여부 확인 없음(비로그인도 채팅 가능). 메시지 미저장.
- **개선**: 연결/이벤트에서 서버 세션으로 발신자 결정, 비인증 차단. (체크리스트 "사용자 인증")

### 🟠 V-06. 서버측 입력 검증 전무 (전 폼)
- username/password/title/description/price/bio/reason 모두 길이·허용문자·형식 검증 없음.
- `price`는 `TEXT`로 저장되어 음수·문자·초장문 등 임의 값 허용(숫자·범위 검증 없음).
- **개선**: 서버측 화이트리스트 검증(길이·형식·범위), 필수값 체크, 실패 시 안전한 오류. (체크리스트 "서버측 입력 검증", "폼 입력 검증", "데이터 무결성")

### 🟠 V-07. 채팅 메시지 검증·길이 제한·Rate Limiting 부재 (`app.py:203-206`)
- 메시지 길이/내용 검증 없음, 스팸·플러딩 제한 없음. 대용량·고빈도 메시지로 DoS/도배 가능.
- **개선**: 서버측 길이·내용 검증, 사용자별 rate limit. (체크리스트 "메시지 내용 검증", "메시지 검증", "Rate Limiting")

### 🟠 V-08. 신고 기능 남용·무결성 취약 (`app.py:183-200`)
- `target_id` 존재 여부 검증 없음(가짜 대상 신고 가능), **자기 신고·중복 신고 제한 없음**, 사유 형식 검증 없음.
- 임계치 기반 차단/휴면 로직 없음, 관리자 검토·감사 로그 없음.
- **개선**: 대상 존재·유형 검증, (reporter,target) 중복 방지, 자기 신고 금지, 임계치→상품 차단/유저 휴면, 감사 로그, 관리자 검토. (체크리스트 "신고 남용 방지", "데이터 무결성 및 로그 관리")

### 🟠 V-09. 로그인 실패 제한 부재 (`app.py:89-105`)
- 실패 횟수 제한·계정 잠금·지연 없음 → 무차별 대입(brute force) 가능. 사용자 열거도 용이.
- **개선**: 실패 횟수 카운트+잠금/지연(time-out). (체크리스트 "실패 로그인 방어")

### 🟠 V-10. 접근제어/소유권 검증 미비 + 상품 관리 기능 부재
- 상품 수정·삭제 기능 자체가 없음(요구사항 미충족). 향후 추가 시 소유자 검증(IDOR 방지) 필요.
- 관리자 역할(role) 개념 없음 → 관리자 기능 불가.
- **개선**: 상품 수정·삭제에 로그인+소유자 검증, `role` 도입, 관리자 라우트 분리. (체크리스트 "인증된 사용자만 등록", "소유자 확인")

### 🟡 V-11. 세션 쿠키 보안 속성/만료/재인증 부재
- `SESSION_COOKIE_SECURE`/`SameSite` 미설정, 세션 만료 시간 없음, 비밀번호 변경 등 민감 작업 재인증 없음.
- **개선**: `SESSION_COOKIE_HTTPONLY=True`(기본), `SECURE`(HTTPS), `SAMESITE='Lax'`, `PERMANENT_SESSION_LIFETIME`, 민감 작업 재인증. (체크리스트 "세션 쿠키 설정", "세션 만료 및 재인증")

### 🟡 V-12. 보안 헤더 부재
- CSP, X-Frame-Options, X-Content-Type-Options 등 미적용 → 클릭재킹·MIME 스니핑·XSS 완화 부재.
- **개선**: `after_request`로 보안 헤더 일괄 적용(또는 flask-talisman). (체크리스트 "보안 헤더 설정")

### 🟡 V-13. ORM 미사용 (체크리스트 명시 항목 미충족)
- 현재 쿼리는 **파라미터 바인딩되어 있어 즉각적 SQL Injection은 없음**(양호). 그러나 공식 체크리스트 "ORM 및 파라미터 바인딩" 항목은 SQLAlchemy ORM 사용을 요구.
- **개선**: SQLAlchemy ORM 전환, 제약조건·외래키·인덱스 명시. (체크리스트 "ORM 및 파라미터 바인딩")

### 🟡 V-14. DB 스키마 취약 (`app.py:26-58`)
- `price TEXT`(숫자 아님), 외래키 없음, 사용자 `role`·`status`(휴면), 상품 `status`(차단), 타임스탬프, 감사 로그, 잔액(송금) 없음.
- **개선**: 타입·제약·외래키·상태·역할·타임스탬프·감사 테이블 도입. (체크리스트 "데이터 무결성")

### 🟡 V-15. XSS — 프레임워크 기본 autoescape에만 의존 (심층 방어 부재)
- Jinja2 자동 이스케이프가 켜져 있어 `{{ product.title }}`, `{{ product.description }}`, `{{ user.bio }}` 등의 **직접적 저장형 XSS는 현재 차단**됨.
- 그러나 서버측 입력 sanitization이 전혀 없어, `|safe` 사용/JSON 임베드/autoescape 해제 시 즉시 취약. 특히 `dashboard.html`의 `'username': "{{ user.username }}"`처럼 **JS 문자열 컨텍스트에 값 삽입**하는 패턴은 위험한 안티패턴(향후 값 확장 시 컨텍스트 이스케이프 실패 가능).
- **개선**: 서버측 입력 검증+출력 인코딩을 심층 방어로 추가, JS 컨텍스트 값 삽입 지양(데이터는 `data-*`/JSON 안전 직렬화). (체크리스트 "XSS 방어")

### 🔵 V-16. 오류/예외 처리 부재
- try/except 없음 → DB 오류 등에서 예외가 그대로 전파(디버그 모드와 결합 시 정보 노출).
- **개선**: 서비스 계층 예외 처리, 사용자에겐 일반 메시지, 서버 로그엔 민감정보 제외 기록. (체크리스트 "에러 및 예외 처리")

### 🔵 V-17. 외부 CDN 스크립트 무결성 미검증 (`base.html`)
- `socket.io.js`를 cdnjs에서 로드하며 SRI(무결성 해시) 없음. CDN 변조 시 공격 코드 주입 가능.
- **개선**: 정적 파일 로컬 호스팅 또는 SRI 해시 + CSP 허용 출처 제한.

### 🔵 V-18. 상품 사진 기능 없음 (요구사항 미충족)
- 슬라이드 25쪽은 상품에 사진 표시를 요구하나 미구현. 향후 파일 업로드 도입 시 확장자·MIME·크기 검증, 난수 파일명 필수.

---

## 2. 체크리스트 대비 현황 (공식 `secure_coding_checklist.csv` 27개 항목)

> 참고: 슬라이드 31쪽은 22행까지만 보였으나, 실제 CSV에는 **"전체 시스템" 섹션 6개 항목**(ORM, DB 권한, 보안 헤더, HTTPS, 에러 처리, 라이브러리 관리)이 추가로 있어 총 27개 항목이다.

| 섹션 | 항목 | 스타터 상태 |
|------|------|-------------|
| 회원가입·프로필 | 서버측 입력 검증 | ❌ V-06 |
| | CSRF 보호 | ❌ V-03 |
| | 비밀번호 보안 | ❌ V-02 |
| | 세션 쿠키 설정 | ❌ V-11 |
| | 세션 만료 및 재인증 | ❌ V-11 |
| | 실패 로그인 방어 | ❌ V-09 |
| | 오류 메시지 | ❌ V-04/V-16 |
| 상품 등록·관리 | 폼 입력 검증 | ❌ V-06 |
| | XSS 방어 | ⚠️ 기본 autoescape만 (V-15) |
| | 인증된 사용자만 등록 | ⚠️ 등록은 세션 체크, 수정·삭제 기능 없음 (V-10) |
| | 소유자 확인 | ❌ 기능 없음 (V-10) |
| | 데이터 무결성 | ❌ V-06/V-14 |
| 실시간 채팅 | 메시지 내용 검증 | ❌ V-07 |
| | 사용자 인증 | ❌ V-05 |
| | 메시지 검증 | ❌ V-07 |
| | Rate Limiting | ❌ V-07 |
| | 연결 암호화(WSS) | ❌ 운영 구성 없음 |
| 안전 거래·신고 | 폼 입력 검증 | ❌ V-06/V-08 |
| | 인증된 사용자 접근 | ✅ 세션 체크 있음 (`report`) |
| | 데이터 무결성 및 로그 관리 | ❌ V-08 |
| | 신고 남용 방지 | ❌ V-08 |
| 전체 시스템 | ORM 및 파라미터 바인딩 | ⚠️ 파라미터 바인딩 O, ORM X (V-13) |
| | 데이터베이스 권한 | ❌ 최소권한 개념 없음 |
| | 보안 헤더 설정 | ❌ V-12 |
| | HTTPS 적용 | ❌ 운영 구성 없음 |
| | 에러 및 예외 처리 | ❌ V-04/V-16 |
| | 라이브러리 및 의존성 관리 | ⚠️ 버전 고정/점검 체계 없음 |

**요약**: 27개 항목 중 명확 충족 1개(신고 접근제어), 부분 충족 4개, 미충족 22개.

---

## 3. 즉각적 SQL Injection 여부 (별도 확인)

- `app.py`의 모든 쿼리는 `?` 파라미터 바인딩 사용 → **문자열 포매팅 기반 SQLi 없음**(양호).
- 단, 공식 체크리스트는 ORM을 요구하므로 P2에서 SQLAlchemy로 전환(V-13).

---

## 4. 다음 단계(P1) 연결

1. 이 감사 결과의 각 V-xx를 요구사항 추적표·위협 모델에 매핑.
2. P2 보안 공통 기반에서 V-01~V-04, V-09, V-11, V-12, V-16 우선 해소.
3. 기능 단계(P3~P8)에서 각 기능별 V-05~V-08, V-10, V-13~V-15, V-18 해소.
4. P9에서 27개 체크리스트 전수 재점검(after 증적) + 침투 테스트.
5. baseline 커밋 `f0dd4ba`를 "before" 기준으로 보존하여 before/after 비교에 사용.
