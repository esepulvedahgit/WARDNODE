import pytest

from app import create_app
from app.config import Config


from app.models import ROLE_ADMIN


def test_security_headers_are_set(client):
    response = client.get("/proxy/")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "camera=()" in response.headers["Permissions-Policy"]


def test_csrf_token_is_rendered_for_forms(client, login_as):
    login_as(ROLE_ADMIN)
    response = client.get("/proxy/")
    body = response.get_data(as_text=True)

    assert 'name="csrf_token"' in body
    assert 'meta name="csrf-token"' in body


def test_csrf_blocks_mutating_request_when_enabled():
    class CsrfEnabledTestConfig(Config):
        TESTING = True
        SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
        WTF_CSRF_ENABLED = True
        RATELIMIT_ENABLED = False

    app = create_app(CsrfEnabledTestConfig)
    with app.app_context():
        from app.extensions import db

        db.create_all()

    client = app.test_client()
    response = client.post("/auth/setup")

    # CSRFError interceptado: redirige (302) o devuelve 400 según el handler activo
    assert response.status_code in (302, 400)


def test_secure_cookie_config_can_be_enabled():
    class SecureCookieConfig(Config):
        TESTING = True
        SESSION_COOKIE_SECURE = True

    app = create_app(SecureCookieConfig)

    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Strict"
    assert app.config["SESSION_COOKIE_SECURE"] is True


# ── #2: SECRET_KEY guard ──────────────────────────────────────────────────────

def test_production_config_rejects_default_secret_key():
    class BadKeyConfig(Config):
        DEBUG = False
        TESTING = False
        PUBLIC_BASE_URL = "https://example.com"
        SECRET_KEY = "dev-secret-key"

    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app(BadKeyConfig)


def test_production_config_rejects_change_me_key():
    class BadKeyConfig(Config):
        DEBUG = False
        TESTING = False
        PUBLIC_BASE_URL = "https://example.com"
        SECRET_KEY = "change-me"

    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app(BadKeyConfig)


def test_production_config_rejects_empty_secret_key():
    class BadKeyConfig(Config):
        DEBUG = False
        TESTING = False
        PUBLIC_BASE_URL = "https://example.com"
        SECRET_KEY = ""

    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app(BadKeyConfig)


def test_production_config_accepts_strong_secret_key():
    import secrets

    class GoodKeyConfig(Config):
        DEBUG = False
        TESTING = False
        PUBLIC_BASE_URL = "https://example.com"
        SECRET_KEY = secrets.token_hex(32)

    app = create_app(GoodKeyConfig)
    assert app is not None


# ── #1: validación de dominio ─────────────────────────────────────────────────

from app.proxy.validators import is_valid_domain, is_valid_email


@pytest.mark.parametrize("domain", [
    "example.com",
    "sub.example.com",
    "my-site.example.co.uk",
    "a.io",
    "xn--nxasmq6b.com",
])
def test_valid_domains_accepted(domain):
    assert is_valid_domain(domain) is True


@pytest.mark.parametrize("domain", [
    "",
    "localhost",
    "evil.com;\n}",
    "evil.com; alias /etc/;",
    "no spaces allowed.com",
    ".leading-dot.com",
    "-leading-dash.com",
    "trailing-.com",
    "a" * 64 + ".com",
])
def test_invalid_domains_rejected(domain):
    assert is_valid_domain(domain) is False


@pytest.mark.parametrize("email", [
    "user@example.com",
    "user+tag@sub.example.co.uk",
    "admin@wardnode.io",
])
def test_valid_emails_accepted(email):
    assert is_valid_email(email) is True


@pytest.mark.parametrize("email", [
    "",
    "user @example.com",
    "user\nexample.com",
    "--email user@example.com",
    "notanemail",
    "user@",
])
def test_invalid_emails_rejected(email):
    assert is_valid_email(email) is False


# ── #4: ctl: bloqueado en reglas ModSecurity ──────────────────────────────────

from app.proxy.custom_rules import validate_custom_rule


def test_ctl_ruleengine_off_blocked():
    errors = validate_custom_rule(
        "test", 'SecAction "id:1000001,phase:1,pass,nolog,ctl:ruleEngine=Off"'
    )
    assert any("ctl:" in e for e in errors)


def test_ctl_ruleengine_detectiononly_blocked():
    errors = validate_custom_rule(
        "test", 'SecAction "id:1000001,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"'
    )
    assert any("ctl:" in e for e in errors)


def test_ctl_requestbodyaccess_off_blocked():
    errors = validate_custom_rule(
        "test", 'SecAction "id:1000001,phase:1,pass,nolog,ctl:requestBodyAccess=Off"'
    )
    assert any("ctl:" in e for e in errors)


def test_ctl_removebyid_blocked():
    errors = validate_custom_rule(
        "test", 'SecAction "id:1000001,phase:1,pass,nolog,ctl:ruleRemoveById=920000"'
    )
    assert any("ctl:" in e for e in errors)


def test_valid_secrule_without_ctl_passes():
    errors = validate_custom_rule(
        "block-scanner",
        'SecRule REQUEST_URI "@contains /etc/passwd" "id:1000002,phase:1,deny,status:403,log"',
    )
    assert errors == []


# ── #8: directivas peligrosas en nginx_extra ─────────────────────────────────

from app.proxy.nginx_extra import validate_nginx_extra_config


def test_proxy_pass_blocked_in_server_snippet():
    errors = validate_nginx_extra_config("proxy_pass http://evil.internal;", "")
    assert any("proxy_pass" in e for e in errors)


def test_proxy_pass_blocked_in_location_snippet():
    errors = validate_nginx_extra_config("", "proxy_pass http://169.254.169.254;")
    assert any("proxy_pass" in e for e in errors)


# ── #9: Excepciones WAF por ID de regla CRS ──────────────────────────────────

from app.proxy.custom_rules import validate_rule_exclusion


def test_rule_exclusion_valid_crs_id():
    rule_id, errors = validate_rule_exclusion("942100", "Falso positivo en token")
    assert errors == []
    assert rule_id == 942100


def test_rule_exclusion_empty_id_rejected():
    rule_id, errors = validate_rule_exclusion("", "")
    assert rule_id is None
    assert any("obligatorio" in e for e in errors)


def test_rule_exclusion_non_integer_rejected():
    rule_id, errors = validate_rule_exclusion("abc", "")
    assert rule_id is None
    assert any("entero" in e for e in errors)


def test_rule_exclusion_non_integer_with_spaces_rejected():
    rule_id, errors = validate_rule_exclusion("942100; rm -rf /", "")
    assert rule_id is None
    assert any("entero" in e for e in errors)


def test_rule_exclusion_own_rule_range_rejected():
    """IDs del rango 1M+ son reglas propias, no reglas CRS."""
    rule_id, errors = validate_rule_exclusion("1000001", "")
    assert rule_id is None
    assert any("personalizadas" in e for e in errors)


def test_rule_exclusion_below_crs_range_rejected():
    rule_id, errors = validate_rule_exclusion("123", "")
    assert rule_id is None
    assert any("900000" in e for e in errors)


def test_rule_exclusion_above_all_ranges_rejected():
    rule_id, errors = validate_rule_exclusion("8000000", "")
    assert rule_id is None
    assert any("900000" in e or "1000000" in e for e in errors)


def test_rule_exclusion_critical_rule_rejected():
    """Las reglas de scoring/bloqueo no pueden excluirse."""
    rule_id, errors = validate_rule_exclusion("949110", "")
    assert rule_id is None
    assert any("crítica" in e for e in errors)


def test_rule_exclusion_critical_outbound_rejected():
    rule_id, errors = validate_rule_exclusion("959100", "")
    assert rule_id is None
    assert any("crítica" in e for e in errors)


def test_rule_exclusion_comment_too_long_rejected():
    comment = "x" * 201
    rule_id, errors = validate_rule_exclusion("942100", comment)
    assert rule_id is None
    assert any("200" in e for e in errors)


def test_rule_exclusion_comment_max_length_accepted():
    comment = "x" * 200
    rule_id, errors = validate_rule_exclusion("942100", comment)
    assert errors == []
    assert rule_id == 942100


def test_return_blocked_in_nginx_extra():
    errors = validate_nginx_extra_config("return 301 https://evil.com;", "")
    assert any("return" in e for e in errors)


def test_add_header_blocked_in_nginx_extra():
    errors = validate_nginx_extra_config('add_header X-Evil "injected";', "")
    assert any("add_header" in e for e in errors)


def test_rewrite_blocked_in_nginx_extra():
    errors = validate_nginx_extra_config("rewrite ^/(.*)$ https://evil.com/$1;", "")
    assert any("rewrite" in e for e in errors)


def test_mirror_blocked_in_nginx_extra():
    errors = validate_nginx_extra_config("mirror /exfil;", "")
    assert any("mirror" in e for e in errors)
