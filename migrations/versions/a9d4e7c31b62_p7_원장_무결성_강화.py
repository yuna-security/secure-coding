"""P7 원장 무결성·지급 멱등성 강화

Revision ID: a9d4e7c31b62
Revises: f41c8b7d2a10
Create Date: 2026-07-24
"""
import sqlalchemy as sa
from alembic import op


revision = "a9d4e7c31b62"
down_revision = "f41c8b7d2a10"
branch_labels = None
depends_on = None


def upgrade():
    # 기존 지급 원장이 있다면 새 NOT NULL 의미의 멱등 키를 먼저 부여한다.
    op.execute(
        "UPDATE transfer SET idempotency_key = "
        "'legacy-grant-' || lower(hex(randomblob(16))) "
        "WHERE kind = 'grant' AND idempotency_key IS NULL"
    )

    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.drop_constraint("ck_user_balance_nonneg", type_="check")
        batch_op.create_check_constraint(
            "ck_user_balance_range",
            "balance between 0 and 1000000000000",
        )

    with op.batch_alter_table("transfer", schema=None) as batch_op:
        batch_op.drop_constraint("ck_transfer_amount_pos", type_="check")
        batch_op.drop_constraint("ck_transfer_kind", type_="check")
        batch_op.create_check_constraint(
            "ck_transfer_amount_range",
            "amount between 1 and 1000000000",
        )
        batch_op.create_check_constraint(
            "ck_transfer_memo_length",
            "length(memo) <= 200",
        )
        batch_op.create_check_constraint(
            "ck_transfer_kind",
            "(kind = 'transfer' AND sender_id IS NOT NULL "
            "AND sender_id <> receiver_id AND idempotency_key IS NOT NULL) "
            "OR (kind = 'grant' AND sender_id IS NULL "
            "AND idempotency_key IS NOT NULL)",
        )

    op.create_index(
        "uq_transfer_grant_idempotency",
        "transfer",
        ["idempotency_key"],
        unique=True,
        sqlite_where=sa.text("kind = 'grant'"),
        postgresql_where=sa.text("kind = 'grant'"),
    )
    op.execute(
        "CREATE TRIGGER IF NOT EXISTS transfer_no_update "
        "BEFORE UPDATE ON transfer BEGIN "
        "SELECT RAISE(ABORT, 'transfer ledger is append-only'); END"
    )
    op.execute(
        "CREATE TRIGGER IF NOT EXISTS transfer_no_delete "
        "BEFORE DELETE ON transfer BEGIN "
        "SELECT RAISE(ABORT, 'transfer ledger is append-only'); END"
    )


def downgrade():
    op.execute("DROP TRIGGER IF EXISTS transfer_no_update")
    op.execute("DROP TRIGGER IF EXISTS transfer_no_delete")
    op.drop_index("uq_transfer_grant_idempotency", table_name="transfer")

    with op.batch_alter_table("transfer", schema=None) as batch_op:
        batch_op.drop_constraint("ck_transfer_amount_range", type_="check")
        batch_op.drop_constraint("ck_transfer_memo_length", type_="check")
        batch_op.drop_constraint("ck_transfer_kind", type_="check")
        batch_op.create_check_constraint(
            "ck_transfer_amount_pos",
            "amount > 0",
        )
        batch_op.create_check_constraint(
            "ck_transfer_kind",
            "(kind = 'transfer' AND sender_id IS NOT NULL "
            "AND sender_id <> receiver_id AND idempotency_key IS NOT NULL) "
            "OR (kind = 'grant' AND sender_id IS NULL)",
        )

    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.drop_constraint("ck_user_balance_range", type_="check")
        batch_op.create_check_constraint(
            "ck_user_balance_nonneg",
            "balance >= 0",
        )
