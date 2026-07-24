"""P5 채팅 내용 무결성 제약 추가

Revision ID: f41c8b7d2a10
Revises: 6254b4428cff
Create Date: 2026-07-24
"""
from alembic import op


# revision identifiers, used by Alembic.
revision = "f41c8b7d2a10"
down_revision = "6254b4428cff"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("chat_message", schema=None) as batch_op:
        batch_op.create_check_constraint(
            "ck_chat_content_length",
            "length(trim(content)) between 1 and 500",
        )


def downgrade():
    with op.batch_alter_table("chat_message", schema=None) as batch_op:
        batch_op.drop_constraint(
            "ck_chat_content_length",
            type_="check",
        )
