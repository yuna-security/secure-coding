# Tiny Second-hand Shopping Platform (Secure Coding)

플랫폼 포인트 기반 중고거래 플랫폼. Flask 앱 팩토리 + Blueprint + 서비스 계층으로
구현했고, 회원가입·상품·실시간 채팅·신고/차단·송금·검색·관리자(R1~R7)를 모두 포함한다.
설계·보안 근거는 [`docs/`](docs/)에, 공식 27항목 체크리스트 점검은
[`docs/CHECKLIST_VERIFICATION.ko.md`](docs/CHECKLIST_VERIFICATION.ko.md)에 있다.

## 주요 기능 (R1~R7)

| 요구 | 기능 |
|------|------|
| R1 | 회원가입/로그인·로그아웃, 프로필 조회·소개글 수정, 비밀번호 변경(재인증) |
| R2 | 상품 등록(+이미지)·목록·상세·수정·삭제(소유자), 공개 조회 |
| R3 | 전체 실시간 채팅 + 1:1 DM (Socket.IO, 참여자 격리) |
| R4 | 사용자·상품 신고, 임계치 자동 차단/휴면, 남용 방지 |
| R5 | 사용자 간 포인트 송금(원자적·멱등·불변 원장), 관리자 지급(grant) |
| R6 | 상품 검색(제목·설명, 정렬 허용목록) |
| R7 | 관리자: 사용자/상품 상태 관리, 신고 검토·복구, 거래·감사 로그 열람 |

## 기술 스택

- Python 3.13, Flask 3, Flask-SQLAlchemy + Flask-Migrate(Alembic), SQLite
- Flask-Login(세션), Flask-WTF(CSRF), Flask-Limiter(Rate Limit), Flask-SocketIO(실시간)
- Argon2id(비밀번호 해시), Pillow(이미지 검증·재인코딩)

## 요구 사항 · 설치

Python 3.13 기준. 가상환경 + pip 사용을 권장한다.

```bash
git clone https://github.com/yuna-security/secure-coding.git
cd secure-coding
python -m venv .venv
# Windows: .venv\Scripts\activate   /   macOS·Linux: source .venv/bin/activate
python -m pip install --upgrade pip==26.1.2
python -m pip install -r requirements.txt
```

> Conda를 쓰는 경우 `conda env create -f enviroments.yaml`도 제공한다. 테스트·CI 기준은 `requirements.txt`이다.

## 환경 변수

`.env.example`를 복사하고 예측 불가능한 `SECRET_KEY`를 설정한다. 운영(`APP_ENV=prod`)은
빈 키로 시작되지 않는다.

```powershell
# Windows PowerShell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

```bash
# macOS·Linux
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

출력된 값을 `.env`의 `SECRET_KEY=` 뒤에 넣는다. `.env`는 Git에 포함하지 않는다.

| 변수 | 설명 | 기본 |
|------|------|------|
| `APP_ENV` | 실행 환경 `dev`\|`prod` | `dev` |
| `SECRET_KEY` | 세션 서명 키(운영 필수) | (dev는 자동 임시키) |
| `DATABASE_URL` | DB 연결 문자열 | `sqlite:///market.db` |
| `HOST` / `PORT` | 개발 서버 바인딩 | `127.0.0.1` / `5000` |
| `TRUST_PROXY_HEADERS` | 신뢰할 단일 프록시 바로 뒤에서만 `1` | `0` |
| `ADMIN_PASSWORD` | `create-admin`용(미설정 시 안전 프롬프트) | — |

기본 SQLite URI의 실제 파일은 Flask instance 경로인 `instance/market.db`에 생성된다.

## 데이터베이스 초기화 · 관리자 생성

```bash
python -m flask --app app db upgrade
python -m flask --app app create-admin <관리자아이디>  # 환경변수 또는 숨김 프롬프트
```

Windows 운영 환경에서는 초기화 후 `instance/`의 상속 ACL을 제거하고 앱 실행 사용자,
SYSTEM, Administrators만 허용한다. PowerShell에서 `$me`를 확인한 뒤 실행한다.

```powershell
$me = "$env:USERDOMAIN\$env:USERNAME"
icacls instance /inheritance:r /T
icacls instance /grant:r "${me}:F" "*S-1-5-18:F" "*S-1-5-32-544:F" /T
icacls instance /grant:r "${me}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
icacls instance\uploads /grant:r "${me}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
```

POSIX에서는 앱이 SQLite·업로드 파일 `0600`, `instance/`·`uploads/` `0700`을 적용한다.

## 실행

```bash
python app.py
```

기본 접속은 `http://127.0.0.1:5000`이다. 이 명령은 로컬 개발과 제한된 실습용이며
인터넷에 직접 공개하는 운영 서버가 아니다. 운영은 `wsgi.py`의 `app`을 WebSocket 지원
WSGI 서버와 HTTPS/WSS 역방향 프록시 뒤에서 로드한다.

## 테스트

```bash
python -m pytest -q
```

기능(P2~P8)·체크리스트/침투(P9) 테스트로 구성된다. 의존성 취약점 점검:

```bash
python -m pip install pip-audit==2.10.1
PYTHONUTF8=1 python -X utf8 -m pip_audit -r requirements.txt  # macOS·Linux
```

Windows PowerShell에서는 먼저 `$env:PYTHONUTF8="1"`을 실행한 뒤
`python -X utf8 -m pip_audit -r requirements.txt`를 실행한다.

## 핸드폰·외부 접속 (HTTPS/WSS)

로컬 개발 서버는 HTTP다. 실제 기기에서 HTTPS/WSS로 테스트하려면 TLS를 종료하는
역방향 프록시(예: ngrok)로 포워딩한다. 터널 테스트에서도 앱 포트는 loopback에만
바인딩하고, `APP_ENV=prod`로 Secure 쿠키·HSTS를 활성화한다.

```bash
# .env의 관련 값
APP_ENV=prod
HOST=127.0.0.1
TRUST_PROXY_HEADERS=1
# SECRET_KEY=<충분히 긴 무작위 값>

# 터미널 1
python app.py

# 터미널 2
ngrok http 5000
```

발급된 `https://<subdomain>.ngrok-free.app`로 접속한다. 같은 HTTPS 출처의 Socket.IO는
`wss://`로 업그레이드된다. `TRUST_PROXY_HEADERS=1`은 앱 포트가 정확히 한 단계의 신뢰할
프록시에서만 접근 가능한 경우에만 사용한다. 테스트 후 `APP_ENV=dev`,
`TRUST_PROXY_HEADERS=0`으로 복구한다.

> 현재 저장소에는 로컬 HTTPS/HSTS/Secure 쿠키와 TLS 종료 프록시를 통한 실제
> `wss://` WebSocket·인증 메시지 왕복 증적이 있다. ngrok·핸드폰 화면 캡처는
> 계정·단말이 필요한 선택적 제출 보강 자료로 별도 수집할 수 있다.

## 보안 요약

- 인증: Argon2id 해시, 세션 쿠키(HttpOnly/SameSite=Lax, 운영 Secure), 로그인 실패 잠금 + IP Rate Limit, 민감 작업 재인증
- 입력/출력: 전 폼 CSRF(HTTPS는 Referer 동일 출처 강제), 서버측 입력 검증, Jinja 자동 이스케이프 + 채팅 `textContent`
- 접근제어: `@login_required`/소유자·참여자 검증(IDOR), 관리자 RBAC(서비스 계층 재검증)
- 데이터 무결성: 모델 CHECK/UNIQUE, 불변 원장(트리거로 UPDATE/DELETE 차단), 조건부 UPDATE 기반 원자적 상태전이
- 주입 방어: SQLAlchemy ORM 파라미터 바인딩 + 정렬 허용목록
- 운영: 보안 헤더(CSP/XFO/XCTO/Referrer/Permissions/HSTS), 명시적 프록시 신뢰,
  런타임 데이터 최소 권한, 안전한 오류 처리(스택트레이스 미노출), 의존성 버전 고정·감사
- 전 항목 매핑: [`docs/CHECKLIST_VERIFICATION.ko.md`](docs/CHECKLIST_VERIFICATION.ko.md)

## 프로젝트 구조

```
app/
  __init__.py        앱 팩토리(확장·블루프린트·소켓 등록)
  config.py          환경별 설정(dev/test/prod)
  security.py        보안 헤더·오류 처리·SQLite PRAGMA/권한
  models.py          ORM 모델·제약
  extensions.py      확장 인스턴스
  auth/ user/ product/ report/ admin/ chat/ wallet/   기능별 blueprint+service
  templates/ static/ 뷰·정적자원(vendored socket.io 포함)
migrations/          Alembic 마이그레이션
tests/               pytest (test_p2~p10)
docs/                설계·감사·체크리스트·증적
app.py / wsgi.py     개발 실행 / 운영 진입점
```
