import re
import uuid
from datetime import datetime, timezone

from flask_login import UserMixin
from sqlalchemy.orm import validates
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


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
    session_token = db.Column(db.String(32), nullable=False, default=lambda: uuid.uuid4().hex)

    reset_tokens = db.relationship(
        "PasswordResetToken",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    def get_id(self) -> str:
        return f"{self.id}:{self.session_token}"

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)
        self.session_token = uuid.uuid4().hex  # invalida todas las sesiones activas

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def has_role(self, *roles: str) -> bool:
        return self.role in roles


class PasswordResetToken(db.Model, TimestampMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
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
    hsts_mode = db.Column(db.String(20), nullable=False, default="off")
    host_port_blocked = db.Column(db.Boolean, default=False, nullable=False)

    @validates("domain")
    def _validate_domain(self, key, value):
        v = (value or "").strip().lower()
        if not _DOMAIN_RE.match(v):
            raise ValueError(f"Dominio inválido: {v!r}")
        return v

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
    geo_blocklist = db.relationship(
        "GeoBlocklistEntry",
        back_populates="site",
        cascade="all, delete-orphan",
        order_by="GeoBlocklistEntry.country_name",
    )
    rule_exclusions = db.relationship(
        "WafRuleExclusion",
        back_populates="site",
        cascade="all, delete-orphan",
        order_by="WafRuleExclusion.rule_id",
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


class WafRuleExclusion(db.Model, TimestampMixin):
    """Excepción WAF por ID de regla CRS. Genera SecRuleRemoveById dentro del server{} del sitio."""

    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey("site.id"), nullable=False)
    rule_id = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.String(200), nullable=True)
    enabled = db.Column(db.Boolean, default=True, nullable=False)

    site = db.relationship("Site", back_populates="rule_exclusions")

    __table_args__ = (
        db.UniqueConstraint("site_id", "rule_id", name="uq_site_rule_exclusion"),
    )


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
    severity = db.Column(db.String(40), nullable=False, default="medium")
    message = db.Column(db.Text, nullable=False)
    transaction_id = db.Column(db.String(64), nullable=True, unique=True, index=True)

    # Índice compuesto para las agregaciones del SOC (detect.find_candidates y
    # ml.build_training_matrix filtran por ventana temporal y agrupan por IP).
    __table_args__ = (
        db.Index("ix_attack_event_ip_created", "source_ip", "created_at"),
    )

    site = db.relationship("Site", back_populates="attack_events")


class ModSecRawLog(db.Model, TimestampMixin):
    """Registro crudo de eventos ModSecurity tal como llegan del hilo ingest.

    Un registro por transacción ModSecurity (transaction_id único).
    raw_json almacena el JSON completo del audit log para consulta posterior
    sin necesidad de re-parsear desde Docker logs.
    """

    __tablename__ = "modsec_raw_log"

    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(64), nullable=True, unique=True, index=True)
    source_ip = db.Column(db.String(80), nullable=True)
    rule_id = db.Column(db.String(80), nullable=True)
    raw_json = db.Column(db.Text, nullable=False)

    __table_args__ = (
        db.Index("ix_modsec_raw_log_created_at", "created_at"),
        db.Index("ix_modsec_raw_log_source_ip", "source_ip"),
    )


class GeoBlocklistEntry(db.Model, TimestampMixin):
    __table_args__ = (db.UniqueConstraint("site_id", "country_code", name="uq_geo_blocklist_site_country"),)

    id           = db.Column(db.Integer, primary_key=True)
    site_id      = db.Column(db.Integer, db.ForeignKey("site.id", ondelete="CASCADE"), nullable=False)
    country_code = db.Column(db.String(2), nullable=False, index=True)
    country_name = db.Column(db.String(80), nullable=False)
    enabled      = db.Column(db.Boolean, default=True, nullable=False)

    site = db.relationship("Site", back_populates="geo_blocklist")


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


class SocIncident(db.Model, TimestampMixin):
    """Incidente de seguridad correlacionado por el módulo SOC.

    Agrupa AttackEvents de una misma IP origen dentro de una ventana temporal,
    con score heurístico, enriquecimiento de threat intel y estado de revisión.
    """

    __tablename__ = "soc_incident"

    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(80), nullable=False, index=True)
    domain = db.Column(db.String(255), nullable=True)
    window_start = db.Column(db.DateTime, nullable=False)
    window_end = db.Column(db.DateTime, nullable=False, index=True)
    event_count = db.Column(db.Integer, nullable=False, default=0)
    score = db.Column(db.Float, nullable=False, default=0.0)
    # 0–100 heurístico (volumen + diversidad + ratio block + fan-out)
    severity = db.Column(db.String(20), nullable=False, default="medium", index=True)
    # critical · high · medium · low
    status = db.Column(db.String(20), nullable=False, default="nuevo", index=True)
    # nuevo · revisado · descartado · confirmado
    reviewed_by = db.Column(
        db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    reviewed_at = db.Column(db.DateTime, nullable=True)
    review_comment = db.Column(db.String(1000), nullable=True)
    # evidencia escrita de la revisión humana (obligatoria al marcar "revisado")
    abuse_score = db.Column(db.Integer, nullable=True)
    # abuseConfidenceScore 0–100 de AbuseIPDB
    mitre = db.Column(db.Text, nullable=True)
    # JSON: [{"id": "T1190", "name": "..."}]
    ml_score = db.Column(db.Float, nullable=True)
    # 0–100 anomalía IsolationForest (None = sin modelo entrenado o ML off)
    alerted_at = db.Column(db.DateTime, nullable=True)
    # cuándo se envió la alerta (email/Telegram) — base del cooldown anti-spam

    # ── SOAR: bloqueo automático ──────────────────────────────────────────
    blocked = db.Column(db.Boolean, nullable=False, default=False, index=True)
    # True cuando el módulo SOAR ejecutó un bloqueo para este incidente
    blocked_at = db.Column(db.DateTime, nullable=True)
    # timestamp UTC del momento del bloqueo
    blocked_method = db.Column(db.String(20), nullable=True)
    # "crowdsec" | "ufw"
    blocked_until = db.Column(db.DateTime, nullable=True)
    # expiración informativa del ban (solo CrowdSec); None para UFW (permanente)

    __table_args__ = (
        db.Index("ix_soc_incident_ip_status", "source_ip", "status"),
    )

    analyses = db.relationship(
        "SocAnalysis", back_populates="incident", cascade="all, delete-orphan"
    )
    reviewer = db.relationship("User", foreign_keys=[reviewed_by], lazy="select")


class SocAnalysis(db.Model, TimestampMixin):
    """Análisis LLM de un incidente SOC (salida JSON estandarizada)."""

    __tablename__ = "soc_analysis"

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(
        db.Integer,
        db.ForeignKey("soc_incident.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    payload = db.Column(db.Text, nullable=False)
    # JSON normalizado por app/soc/schema.py
    provider = db.Column(db.String(40), nullable=False)
    model = db.Column(db.String(120), nullable=False)
    tokens_in = db.Column(db.Integer, nullable=True)
    tokens_out = db.Column(db.Integer, nullable=True)
    read_at = db.Column(db.DateTime, nullable=True)
    # "auto" (worker) | "manual" (botón retroactivo en el detalle del incidente)
    origin = db.Column(db.String(10), nullable=False, default="auto", server_default="auto")
    manual_reason = db.Column(db.String(200), nullable=True)

    incident = db.relationship("SocIncident", back_populates="analyses")


class ThreatIntelCache(db.Model, TimestampMixin):
    """Cache local de respuestas de threat intel (AbuseIPDB) por IP, con TTL."""

    __tablename__ = "threat_intel_cache"

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(80), nullable=False, unique=True, index=True)
    payload = db.Column(db.Text, nullable=False)
    fetched_at = db.Column(db.DateTime, nullable=False)


class MitreAttackTechnique(db.Model, TimestampMixin):
    """Técnica MITRE ATT&CK Enterprise sincronizada desde el CTI oficial.

    Poblada por app/soc/mitre_cti.py:sync_mitre_attack(). Sirve como referencia
    autorizada de nombres/tácticas y para validar IDs sugeridos por el LLM
    (anti-alucinación en schema._coerce_mitre).
    """

    __tablename__ = "mitre_attack_technique"

    id = db.Column(db.Integer, primary_key=True)
    technique_id = db.Column(db.String(20), unique=True, nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    tactic = db.Column(db.String(255))  # "initial-access,execution" (comma-join)
    is_subtechnique = db.Column(db.Boolean, default=False)
    synced_at = db.Column(db.DateTime, nullable=False)


class DdosBanEvent(db.Model):
    """Evento de ban registrado por CrowdSec (SSH brute-force).

    Poblado por app/ddos/ingest.py desde 'cscli alerts list -o json'.
    cs_alert_id garantiza deduplicación: si el poller vuelve a ver el mismo
    alert_id, el IntegrityError provoca un rollback silencioso — mismo patrón
    que AttackEvent.transaction_id.
    """

    __tablename__ = "ddos_ban_event"

    id           = db.Column(db.Integer, primary_key=True)
    cs_alert_id  = db.Column(db.Integer, unique=True, nullable=False, index=True)
    source_ip    = db.Column(db.String(80), nullable=False)
    scenario     = db.Column(db.String(120), nullable=False, default="unknown")
    country_code = db.Column(db.String(2), nullable=True)
    events_count = db.Column(db.Integer, nullable=False, default=1)
    created_at   = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    expires_at   = db.Column(db.DateTime, nullable=True)


class SocMlModel(db.Model, TimestampMixin):
    """Modelo ML serializado (IsolationForest) para scoring de anomalías SOC.

    SEGURIDAD: blob es un pickle de joblib. Solo se deserializan blobs escritos
    por app/soc/ml.py:train_model() (sin input de usuario). Jamás cargar modelos
    de origen externo en esta tabla.
    """

    __tablename__ = "soc_ml_model"

    id = db.Column(db.Integer, primary_key=True)
    blob = db.Column(db.LargeBinary, nullable=False)
    n_samples = db.Column(db.Integer, nullable=False)
    features = db.Column(db.Text, nullable=False)  # JSON list de nombres de features
    score_min = db.Column(db.Float, nullable=False)  # calibración decision_function
    score_max = db.Column(db.Float, nullable=False)
    trained_at = db.Column(db.DateTime, nullable=False)
