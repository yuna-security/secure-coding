import os
import shutil
import uuid

import pytest

from app import create_app
from app.extensions import db as _db


@pytest.fixture
def app():
    app = create_app("test")
    # 프로젝트의 instance 아래에서 파일 권한·정리 동작까지 검증한다.
    os.makedirs(app.instance_path, exist_ok=True)
    tmp_upload = os.path.join(app.instance_path, f"uploads_test_{uuid.uuid4().hex}")
    os.makedirs(tmp_upload)
    app.config["UPLOAD_FOLDER"] = tmp_upload
    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()
    shutil.rmtree(tmp_upload, ignore_errors=True)


@pytest.fixture
def client(app):
    return app.test_client()
