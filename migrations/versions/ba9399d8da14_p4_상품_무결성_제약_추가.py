"""P4 상품 무결성 제약 추가

Revision ID: ba9399d8da14
Revises: ad7e0a22b1a9
Create Date: 2026-07-24 05:20:19.926589

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'ba9399d8da14'
down_revision = 'ad7e0a22b1a9'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('product', schema=None) as batch_op:
        batch_op.drop_constraint('ck_product_price_pos', type_='check')
        batch_op.create_check_constraint(
            'ck_product_title_length',
            'length(trim(title)) between 1 and 120',
        )
        batch_op.create_check_constraint(
            'ck_product_description_length',
            'length(description) <= 4000',
        )
        batch_op.create_check_constraint(
            'ck_product_price_range',
            'price between 1 and 1000000000',
        )
        batch_op.create_unique_constraint(
            'uq_product_image_filename', ['image_filename']
        )


def downgrade():
    with op.batch_alter_table('product', schema=None) as batch_op:
        batch_op.drop_constraint('uq_product_image_filename', type_='unique')
        batch_op.drop_constraint('ck_product_price_range', type_='check')
        batch_op.drop_constraint(
            'ck_product_description_length', type_='check'
        )
        batch_op.drop_constraint('ck_product_title_length', type_='check')
        batch_op.create_check_constraint('ck_product_price_pos', 'price > 0')
