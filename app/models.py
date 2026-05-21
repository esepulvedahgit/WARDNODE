from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db


ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
ROLE_READER = "reader"
ROLES = (ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)


class TimestampMixin:
    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class User(UserMixin, db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(160), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(40), nullable=False, default=ROLE_READER)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    totp_secret = db.Column(db.Text, nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)

    reset_tokens = db.relationship(
        "PasswordResetToken",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def has_role(self, *roles: str) -> bool:
        return self.role in roles


class PasswordResetToken(db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token_hash = db.Column(db.String(255), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship("User", back_populates="reset_tokens")

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at.replace(tzinfo=timezone.utc)

    @property
    def is_usable(self) -> bool:
        return self.used_at is None and not self.is_expired


class Site(db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    domain = db.Column(db.String(255), unique=True, nullable=False, index=True)
    upstream_url = db.Column(db.String(500), nullable=False)
    waf_enabled = db.Column(db.Boolean, default=False, nullable=False)
    letsencrypt_enabled = db.Column(db.Boolean, default=False, nullable=False)
    letsencrypt_status = db.Column(db.String(20), nullable=False, default="none")
    letsencrypt_error = db.Column(db.Text, nullable=True)
    custom_certificate_path = db.Column(db.String(500), nullable=True)
    custom_certificate_key_path = db.Column(db.String(500), nullable=True)
    is_console = db.Column(db.Boolean, default=False, nullable=False)
    force_https = db.Column(db.Boolean, default=False, nullable=False)

    rule_settings = db.relationship(
        "SiteRuleSetting",
        back_populates="site",
        cascade="all, delete-orphan",
    )
    attack_events = db.relationship(
        "AttackEvent",
        back_populates="site",
        cascade="all, delete-orphan",
        order_by="desc(AttackEvent.created_at)",
    )
    traffic_policy = db.relationship(
        "TrafficPolicy",
        back_populates="site",
        cascade="all, delete-orphan",
        uselist=False,
    )
    security_headers = db.relationship(
        "SecurityHeader",
        back_populates="site",
        cascade="all, delete-orphan",
        order_by="SecurityHeader.position",
    )
    nginx_extra_config = db.relationship(
        "NginxExtraConfig",
        back_populates="site",
        cascade="all, delete-orphan",
        uselist=False,
    )
    custom_rules = db.relationship(
        "CustomModSecurityRule",
        back_populates="site",
        cascade="all, delete-orphan",
        order_by="CustomModSecurityRule.position",
    )
    bot_protection = db.relationship(
        "BotProtectionConfig",
        back_populates="site",
        cascade="all, delete-orphan",
        uselist=False,
    )


class TrafficPolicy(db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey("site.id"), unique=True, nullable=False)
    rate_limit_enabled = db.Column(db.Boolean, default=True, nullable=False)
    requests_per_second = db.Column(db.Integer, default=20, nullable=False)
    burst = db.Column(db.Integer, default=40, nullable=False)
    nodelay = db.Column(db.Boolean, default=True, nullable=False)
    conn_limit_enabled = db.Column(db.Boolean, default=True, nullable=False)
    max_connections = db.Column(db.Integer, default=20, nullable=False)
    key_strategy = db.Column(db.String(40), default="ip", nullable=False)

    site = db.relationship("Site", back_populates="traffic_policy")


class SecurityHeader(db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey("site.id"), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    value = db.Column(db.String(1000), nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    always = db.Column(db.Boolean, default=True, nullable=False)
    position = db.Column(db.Integer, default=0, nullable=False)
    is_default = db.Column(db.Boolean, default=False, nullable=False)

    site = db.relationship("Site", back_populates="security_headers")


class NginxExtraConfig(db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey("site.id"), unique=True, nullable=False)
    enabled = db.Column(db.Boolean, default=False, nullable=False)
    server_snippet = db.Column(db.Text, default="", nullable=False)
    location_snippet = db.Column(db.Text, default="", nullable=False)

    site = db.relationship("Site", back_populates="nginx_extra_config")


class CustomModSecurityRule(db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey("site.id"), nullable=False)
    name = db.Column(db.String(160), nullable=False)
    rule_text = db.Column(db.Text, nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    position = db.Column(db.Integer, default=0, nullable=False)

    site = db.relationship("Site", back_populates="custom_rules")


class RuleCategory(db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), unique=True, nullable=False, index=True)
    name = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    crs_tag = db.Column(db.String(160), nullable=False)
    enabled_by_default = db.Column(db.Boolean, default=False, nullable=False)

    site_settings = db.relationship(
        "SiteRuleSetting",
        back_populates="category",
        cascade="all, delete-orphan",
    )


class SiteRuleSetting(db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey("site.id"), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey("rule_category.id"), nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)

    site = db.relationship("Site", back_populates="rule_settings")
    category = db.relationship("RuleCategory", back_populates="site_settings")

    __table_args__ = (
        db.UniqueConstraint("site_id", "category_id", name="uq_site_rule_category"),
    )


class BotProtectionConfig(db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey("site.id"), unique=True, nullable=False)
    enabled = db.Column(db.Boolean, default=False, nullable=False)

    site = db.relationship("Site", back_populates="bot_protection")


class AttackEvent(db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey("site.id"), nullable=True)
    domain = db.Column(db.String(255), nullable=False, index=True)
    source_ip = db.Column(db.String(80), nullable=False)
    country_code = db.Column(db.String(2), nullable=True, index=True)
    method = db.Column(db.String(16), nullable=False)
    path = db.Column(db.String(1000), nullable=False)
    status_code = db.Column(db.Integer, nullable=False, default=403)
    action = db.Column(db.String(20), nullable=False, default="block")
    category = db.Column(db.String(120), nullable=False, default="unknown")
    rule_id = db.Column(db.String(80), nullable=True)
    severity = db.Column(db.String(40), nullable=False, default="warning")
    message = db.Column(db.Text, nullable=False)
    transaction_id = db.Column(db.String(64), nullable=True, unique=True, index=True)

    site = db.relationship("Site", back_populates="attack_events")


class GeoBlocklistEntry(db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    country_code = db.Column(db.String(2), unique=True, nullable=False, index=True)
    country_name = db.Column(db.String(80), nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)


class AuditLog(db.Model):
    """Registro inmutable de eventos del sistema y acciones de usuario."""
    __tablename__ = "audit_log"

    id           = db.Column(db.Integer, primary_key=True)
    created_at   = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    actor_email  = db.Column(db.String(255), nullable=False, default="sistema")
    actor_id     = db.Column(
        db.Integer,
        db.ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    action        = db.Column(db.String(80),  nullable=False, index=True)
    resource_type = db.Column(db.String(40),  nullable=True)
    resource_name = db.Column(db.String(255), nullable=True)
    detail        = db.Column(db.Text,        nullable=True)   # JSON opcional
    ip_address    = db.Column(db.String(80),  nullable=True)
    severity      = db.Column(db.String(20),  nullable=False, default="info")
    # info · warning · error · critical
    status        = db.Column(db.String(20),  nullable=False, default="success")
    # success · failure

    actor = db.relationship("User", foreign_keys=[actor_id], lazy="select")


class AppConfig(db.Model, TimestampMixin):
    __tablename__ = "app_config"
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(128), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
    encrypted = db.Column(db.Boolean, default=False, nullable=False)

    @classmethod
    def get(cls, key: str) -> str | None:
        row = db.session.execute(db.select(cls).filter_by(key=key)).scalar_one_or_none()
        return row.value if row else None

    @classmethod
    def get_secret(cls, key: str) -> str | None:
        """Como get(), pero auto-descifra si la fila tiene encrypted=True."""
        from app.encryption import decrypt_secret
        row = db.session.execute(db.select(cls).filter_by(key=key)).scalar_one_or_none()
        if row is None:
            return None
        if row.encrypted:
            return decrypt_secret(row.value)
        return row.value

    @classmethod
    def set(cls, key: str, value: str | None, encrypted: bool = False) -> None:
        row = db.session.execute(db.select(cls).filter_by(key=key)).scalar_one_or_none()
        if row is None:
            row = cls(key=key)
            db.session.add(row)
        row.value = value
        row.encrypted = encrypted
        db.session.commit()
