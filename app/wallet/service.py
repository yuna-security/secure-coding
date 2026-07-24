"""송금·지갑 서비스 (P7, R5) — 플랫폼 포인트 원장 무결성(SR-03).

핵심 안전 원칙:
- **원자적 조건부 차감**: `UPDATE user SET balance=balance-:amt WHERE id=:s AND status='active'
  AND balance>=:amt` 의 영향행수==1일 때만 입금·원장 기록으로 진행(V-14, AC5.3).
  경합 송금에서도 잔액이 음수가 되지 않고 정확히 한 번만 반영된다.
- **불변 원장(append-only)**: transfer는 수정·삭제하지 않는다. `user.balance`는 원장과
  대조 가능한 materialized balance(직접 수정 경로 없음, 오직 이 트랜잭션에서만 변경).
- **멱등(AC5.4)**: `(sender_id, idempotency_key)` UNIQUE. 같은 키+같은 수신자/금액이면
  기존 성공 결과를 재응답(무변경), 같은 키+다른 파라미터면 409. 병렬 재전송은 UNIQUE
  위반(IntegrityError)으로 걸러 재응답한다.
- 발신자·수신자 상태를 현재 DB에서 재확인하고, 모든 예외에서 rollback한다.
"""
import re

from flask import current_app
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import Conflict

from ..extensions import db
from ..models import User, Transfer, write_audit
from ..auth.service import ValidationError

_AMOUNT_RE = re.compile(r"^\d+$")
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9_-]+$")


# ---------- 입력 검증 ----------

def parse_amount(raw) -> int:
    raw = str(raw if raw is not None else "").strip()
    if not _AMOUNT_RE.fullmatch(raw):
        raise ValidationError("금액은 0보다 큰 정수여야 합니다.")
    amount = int(raw)
    lo = current_app.config["TRANSFER_AMOUNT_MIN"]
    hi = current_app.config["TRANSFER_AMOUNT_MAX"]
    if not (lo <= amount <= hi):
        raise ValidationError(f"금액은 {lo}~{hi:,} 범위여야 합니다.")
    return amount


def clean_memo(memo) -> str:
    if memo is None:
        memo = ""
    if not isinstance(memo, str):
        raise ValidationError("메모 형식이 올바르지 않습니다.")
    memo = memo.strip()
    limit = current_app.config["TRANSFER_MEMO_MAX"]
    if len(memo) > limit:
        raise ValidationError(f"메모는 최대 {limit}자까지 입력할 수 있습니다.")
    return memo


def validate_idempotency_key(key) -> str:
    if not isinstance(key, str):
        raise ValidationError("요청 식별자가 올바르지 않습니다. 다시 시도하세요.")
    key = key.strip()
    lo = current_app.config["IDEMPOTENCY_KEY_MIN"]
    hi = current_app.config["IDEMPOTENCY_KEY_MAX"]
    if not (lo <= len(key) <= hi) or not _IDEMPOTENCY_RE.fullmatch(key):
        raise ValidationError("요청 식별자가 올바르지 않습니다. 다시 시도하세요.")
    return key


def _active_sender(sender: User) -> User:
    sender_id = getattr(sender, "id", None)
    current = (
        db.session.get(User, sender_id, populate_existing=True) if sender_id else None
    )
    if current is None or not current.is_active or current.role != "user":
        raise ValidationError("활성 상태의 사용자만 송금할 수 있습니다.")
    return current


def _active_recipient(username: str) -> User:
    if not isinstance(username, str):
        raise ValidationError("받는 사람 형식이 올바르지 않습니다.")
    username = username.strip()
    if not username:
        raise ValidationError("받는 사람을 입력하세요.")
    user = User.query.filter_by(username=username).first()
    if user is None or user.status != "active" or user.role != "user":
        raise ValidationError("존재하지 않거나 송금할 수 없는 사용자입니다.")
    return user


# ---------- 송금 (AC5.2~5.4) ----------

def _existing_idempotent(sender_id, key):
    return Transfer.query.filter_by(
        sender_id=sender_id, kind="transfer", idempotency_key=key
    ).first()


def _replay_or_conflict(sender_id, key, recipient_username, amount):
    existing = _existing_idempotent(sender_id, key)
    if existing is None:
        return None
    existing_receiver = db.session.get(User, existing.receiver_id)
    if (
        existing_receiver is not None
        and existing_receiver.username == recipient_username
        and existing.amount == amount
    ):
        return existing
    raise Conflict()


def transfer_points(sender: User, recipient_username: str, amount_raw,
                    memo, idempotency_key) -> Transfer:
    sender = _active_sender(sender)
    amount = parse_amount(amount_raw)
    memo = clean_memo(memo)
    key = validate_idempotency_key(idempotency_key)
    if not isinstance(recipient_username, str):
        raise ValidationError("받는 사람 형식이 올바르지 않습니다.")
    normalized_recipient = recipient_username.strip()

    # 성공한 요청의 재응답은 수신자의 이후 휴면 여부와 무관하게 먼저 처리한다.
    existing = _replay_or_conflict(
        sender.id, key, normalized_recipient, amount
    )
    if existing is not None:
        return existing

    recipient = _active_recipient(normalized_recipient)
    if recipient.id == sender.id:
        raise ValidationError("자기 자신에게는 송금할 수 없습니다.")

    try:
        # 조건부 차감 — 잔액 이내일 때만 1행 갱신(경합·초과 방지).
        debited = User.query.filter(
            User.id == sender.id,
            User.status == "active",
            User.role == "user",
            User.balance >= amount,
        ).update({"balance": User.balance - amount}, synchronize_session=False)
        if debited != 1:
            db.session.rollback()
            replay = _replay_or_conflict(
                sender.id, key, normalized_recipient, amount
            )
            if replay is not None:
                return replay
            raise ValidationError("잔액이 부족합니다.")
        credited = User.query.filter(
            User.id == recipient.id,
            User.status == "active",
            User.role == "user",
            User.balance <= current_app.config["BALANCE_MAX"] - amount,
        ).update({"balance": User.balance + amount}, synchronize_session=False)
        if credited != 1:
            # 수신자가 중간에 비활성화됨 — 전체 롤백.
            raise Conflict()
        ledger = Transfer(
            kind="transfer",
            sender_id=sender.id,
            receiver_id=recipient.id,
            amount=amount,
            memo=memo,
            idempotency_key=key,
        )
        db.session.add(ledger)
        write_audit(
            "user", "transfer", actor_id=sender.id,
            target=recipient.id, detail=str(amount),
        )
        db.session.commit()
        return ledger
    except IntegrityError:
        # 병렬 재전송이 UNIQUE(sender,key)에 걸림 — 기존 성공을 재응답하거나 409.
        db.session.rollback()
        existing = _replay_or_conflict(
            sender.id, key, normalized_recipient, amount
        )
        if existing is not None:
            return existing
        raise Conflict()
    except Exception:
        db.session.rollback()
        raise


# ---------- 조회 (AC5.5) ----------

def get_balance(user: User) -> int:
    current = db.session.get(
        User, getattr(user, "id", None), populate_existing=True
    )
    return current.balance if current is not None else 0


def transaction_history(user_id: str, page: int):
    query = Transfer.query.filter(
        db.or_(Transfer.sender_id == user_id, Transfer.receiver_id == user_id)
    ).order_by(Transfer.created_at.desc())
    return query.paginate(
        page=page, per_page=current_app.config["WALLET_PAGE_SIZE"], error_out=False
    )


def ledger_balance(user_id: str) -> int:
    """원장으로 재계산한 잔액(받은 합계 - 보낸 합계). materialized balance 대조·감사용."""
    def _sum(column):
        return db.session.query(
            db.func.coalesce(db.func.sum(Transfer.amount), 0)
        ).filter(column == user_id).scalar() or 0

    return _sum(Transfer.receiver_id) - _sum(Transfer.sender_id)
