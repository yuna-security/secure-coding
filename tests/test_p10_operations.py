"""P10 운영 경계 테스트 — 역방향 프록시 신뢰는 명시적으로만 활성화한다."""
from flask import request

from app import create_app


FORWARDED_HEADERS = {
    "X-Forwarded-For": "203.0.113.10",
    "X-Forwarded-Proto": "https",
    "X-Forwarded-Host": "example.ngrok-free.app",
}


def _add_probe(app):
    @app.get("/_test/proxy")
    def proxy_probe():
        return {
            "secure": request.is_secure,
            "host": request.host,
            "remote_addr": request.remote_addr,
        }


def test_forwarded_headers_are_ignored_by_default(monkeypatch):
    monkeypatch.delenv("TRUST_PROXY_HEADERS", raising=False)
    app = create_app("test")
    _add_probe(app)
    data = app.test_client().get(
        "/_test/proxy", headers=FORWARDED_HEADERS
    ).get_json()
    assert data["secure"] is False
    assert data["host"] == "localhost"
    assert data["remote_addr"] == "127.0.0.1"


def test_one_trusted_proxy_restores_external_https_origin(monkeypatch):
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "1")
    app = create_app("test")
    _add_probe(app)
    data = app.test_client().get(
        "/_test/proxy", headers=FORWARDED_HEADERS
    ).get_json()
    assert data == {
        "secure": True,
        "host": "example.ngrok-free.app",
        "remote_addr": "203.0.113.10",
    }


def test_socket_origin_check_uses_trusted_external_host(monkeypatch):
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "1")
    app = create_app("test")
    client = app.test_client()
    endpoint = "/socket.io/?EIO=4&transport=polling"
    same_origin = {
        **FORWARDED_HEADERS,
        "Origin": "https://example.ngrok-free.app",
    }
    cross_origin = {
        **FORWARDED_HEADERS,
        "Origin": "https://evil.example",
    }
    assert client.get(endpoint, headers=same_origin).status_code == 200
    assert client.get(endpoint, headers=cross_origin).status_code == 400
