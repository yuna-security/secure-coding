P10 README 재현 검증 (2026-07-24)
================================================
환경: Windows 11, Python 3.13.7, 새 임시 .repro-venv + 깨끗한 임시 DB
목적: README.md의 설치·DB 초기화·관리자 생성·실행·테스트 절차를 처음부터 확인.

[STEP 0] 새 가상환경과 의존성 설치
  -> python -m venv .repro-venv
  -> python -m pip install --upgrade pip==26.1.2
  -> python -m pip install -r requirements.txt
  -> 고정된 직접 의존성과 해결된 전이 의존성 설치 성공

[STEP 1] python -m flask --app app db upgrade
  -> Running upgrade ... -> a9d4e7c31b62 (P7 원장 무결성 강화)
  -> flask --app app db current : a9d4e7c31b62 (head)   [최신 head 도달]

[STEP 2] python -m flask --app app create-admin codex_repro_admin
  -> "관리자 계정 생성: codex_repro_admin"

[STEP 3] python app.py  (HOST=127.0.0.1 PORT=5098, Socket.IO 개발 서버)
  -> GET /          HTTP 200
  -> GET /products  HTTP 200

[STEP 4] pytest -q
  -> 253 passed

결론: README의 절차(새 venv→의존성 설치→db upgrade→create-admin→python app.py→pytest)가
     오류 없이 재현된다. 사용한 임시 가상환경·DB·서버 프로세스는 검증 후 제거했다.
