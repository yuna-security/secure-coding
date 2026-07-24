"""P6 신고 사유 무결성 제약 추가

Revision ID: 6254b4428cff
Revises: ba9399d8da14
Create Date: 2026-07-24 10:38:10.030065

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '6254b4428cff'
down_revision = 'ba9399d8da14'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('report', schema=None) as batch_op:
        batch_op.create_check_constraint(
            'ck_report_reason_length',
            'length(trim(reason)) between 1 and 1000',
        )


def downgrade():
    with op.batch_alter_table('report', schema=None) as batch_op:
        batch_op.drop_constraint(
            'ck_report_reason_length',
            type_='check',
        )
