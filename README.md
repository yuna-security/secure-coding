# Secure Coding

## Tiny Secondhand Shopping Platform

You should add some functions and complete the security requirements.

## Requirements

If you do not have Miniconda (or Anaconda), install it from:
https://docs.anaconda.com/free/miniconda/index.html

```bash
git clone https://github.com/yuna-security/secure-coding.git
cd secure-coding
conda env create -f enviroments.yaml
```

## Usage

환경 예시를 복사하고 예측 불가능한 `SECRET_KEY`를 설정합니다. 운영
(`APP_ENV=prod`)에서는 빈 키로 애플리케이션이 시작되지 않습니다.

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

최초 1회 DB를 초기화한 뒤 개발 서버를 실행합니다.

```bash
flask --app app db upgrade
python app.py
```

기본 접속 주소는 `http://127.0.0.1:5000`입니다. 테스트는 다음 명령으로
실행합니다.

```bash
pytest -q
```

For temporary external testing, ngrok can forward port 5000:

```bash
# optional
sudo snap install ngrok
ngrok http 5000
```

외부 접속 테스트 때만 `.env`의 `HOST=0.0.0.0`을 사용하고, 테스트가 끝나면
기본값으로 되돌립니다. Werkzeug 대화형 디버거는 모든 환경에서 비활성화합니다.

> 현재 README는 P2 보안 공통 기반까지 반영했습니다. 전체 기능·마이그레이션·
> 운영 배포 절차는 구현 진행에 맞춰 확장합니다.
