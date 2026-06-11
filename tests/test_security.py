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

    assert response.status_code == 400


def test_secure_cookie_config_can_be_enabled():
    class SecureCookieConfig(Config):
        TESTING = True
        SESSION_COOKIE_SECURE = True

    app = create_app(SecureCookieConfig)

    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Strict"
    assert app.config["SESSION_COOKIE_SECURE"] is True
