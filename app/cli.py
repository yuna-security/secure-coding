"""CLI 명령: DB 초기화, 관리자 시드.

- `flask init-db` : 테이블 생성(개발용; 운영은 Flask-Migrate 사용)
- `flask create-admin <username>` : 관리자 계정 생성(비밀번호는 환경변수 또는 프롬프트)
"""
import os

import click
from flask import current_app

from .extensions import db
from .models import User, write_audit
from .auth import service


def register_cli(app):
    @app.cli.command("init-db")
    def init_db():
        """모든 테이블 생성(개발/테스트용)."""
        db.create_all()
        click.echo("DB 초기화 완료.")

    @app.cli.command("create-admin")
    @click.argument("username")
    def create_admin(username):
        """관리자 계정 생성. 비밀번호는 ADMIN_PASSWORD 환경변수 또는 안전 입력."""
        username = service.validate_username(username)
        if User.query.filter_by(username=username).first():
            click.echo("이미 존재하는 사용자명입니다.")
            return
        password = os.environ.get("ADMIN_PASSWORD")
        if not password:
            password = click.prompt(
                "관리자 비밀번호", hide_input=True, confirmation_prompt=True
            )
        service.validate_password(password)
        admin = User(
            username=username,
            password_hash=service.hash_password(password),
            role="admin",
        )
        db.session.add(admin)
        write_audit("system", "create_admin", target=username)
        db.session.commit()
        click.echo(f"관리자 계정 생성: {username}")
