from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe

from werkzeug.security import generate_password_hash

from app.extensions import db
from app.models import PasswordResetToken, ROLE_ADMIN, User


def admin_exists() -> bool:
    return db.session.query(User.id).filter_by(role=ROLE_ADMIN, is_active=True).first() is not None


def create_user(email: str, name: str, password: str, role: str) -> User:
    user = User(email=email.strip().lower(), name=name.strip(), role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


def create_password_reset_token(user: User, lifetime_minutes: int) -> tuple[PasswordResetToken, str]:
    raw_token = token_urlsafe(32)
    reset_token = PasswordResetToken(
        user=user,
        token_hash=generate_password_hash(raw_token),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=lifetime_minutes),
    )
    db.session.add(reset_token)
    db.session.commit()
    return reset_token, raw_token


def find_usable_password_reset_token(raw_token: str) -> PasswordResetToken | None:
    from werkzeug.security import check_password_hash

    candidates = PasswordResetToken.query.filter_by(used_at=None).order_by(
        PasswordResetToken.created_at.desc()
    )
    for candidate in candidates:
        if candidate.is_usable and check_password_hash(candidate.token_hash, raw_token):
            return candidate
    return None


def consume_password_reset_token(reset_token: PasswordResetToken, password: str) -> None:
    reset_token.user.set_password(password)
    reset_token.used_at = datetime.now(timezone.utc)
    db.session.commit()

