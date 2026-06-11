import pytest
from app.auth.password_policy import is_valid_password, password_errors
from app.auth.services import create_password_reset_token
from app.models import ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER, PasswordResetToken, User


def test_initial_admin_setup_is_available_before_admin(client):
    response = client.get("/auth/setup")

    assert response.status_code == 200
    assert "Crear admin inicial" in response.get_data(as_text=True)


def test_create_initial_admin_and_login(client):
    response = client.post(
        "/auth/setup",
        data={
            "name": "Admin",
            "email": "admin@example.com",
            "password": "ChangeMe12345!",
            "password_confirm": "ChangeMe12345!",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Iniciar sesi" in response.get_data(as_text=True)

    response = client.post(
        "/auth/login",
        data={"email": "admin@example.com", "password": "ChangeMe12345!"},
        follow_redirects=True,
    )

    assert "Overview" in response.get_data(as_text=True)


def test_setup_closes_after_admin_exists(client, user_factory):
    user_factory(role=ROLE_ADMIN)

    response = client.get("/auth/setup")

    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_admin_can_create_users(client, login_as):
    login_as(ROLE_ADMIN)

    response = client.post(
        "/auth/users",
        data={
            "name": "Operator",
            "email": "operator@example.com",
            "role": ROLE_OPERATOR,
            "password": "ChangeMe12345!",
            "password_confirm": "ChangeMe12345!",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert User.query.filter_by(email="operator@example.com").first() is not None


def test_operator_cannot_create_users(client, login_as):
    login_as(ROLE_OPERATOR)

    response = client.post(
        "/auth/users",
        data={
            "name": "Reader",
            "email": "reader@example.com",
            "role": ROLE_READER,
            "password": "ChangeMe12345!",
            "password_confirm": "ChangeMe12345!",
        },
    )

    assert response.status_code == 403


def test_reader_can_view_but_cannot_mutate_proxy(client, login_as):
    login_as(ROLE_READER)

    response = client.get("/proxy/")
    assert response.status_code == 200

    response = client.post(
        "/proxy/sites",
        data={
            "name": "Demo",
            "domain": "demo.local",
            "upstream_url": "http://demo:8080",
        },
    )
    assert response.status_code == 403


# ── Borrado de usuarios ───────────────────────────────────────────────────────

def test_admin_can_delete_operator(client, login_as, user_factory):
    """Admin puede eliminar un operador; el usuario desaparece de la BD."""
    login_as(ROLE_ADMIN)
    operator = user_factory(email="op@example.com", role=ROLE_OPERATOR)
    op_id = operator.id

    response = client.post(
        f"/auth/users/{op_id}/delete",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert User.query.filter_by(email="op@example.com").first() is None


def test_admin_cannot_delete_admin(client, login_as, user_factory):
    """Admin no puede eliminar otra cuenta de administrador."""
    admin = login_as(ROLE_ADMIN)
    other_admin = user_factory(email="admin2@example.com", role=ROLE_ADMIN)
    other_id = other_admin.id

    response = client.post(
        f"/auth/users/{other_id}/delete",
        follow_redirects=True,
    )

    assert response.status_code == 200
    # El usuario admin debe seguir existiendo
    assert User.query.filter_by(email="admin2@example.com").first() is not None


def test_operator_cannot_delete_user(client, login_as, user_factory):
    """Operador no tiene acceso a la ruta de borrado (403)."""
    login_as(ROLE_OPERATOR)
    target = user_factory(email="reader@example.com", role=ROLE_READER)

    response = client.post(f"/auth/users/{target.id}/delete")

    assert response.status_code == 403


def test_delete_user_cascades_reset_tokens(app, client, login_as, user_factory):
    """Borrar un usuario elimina en cascada sus PasswordResetToken."""
    login_as(ROLE_ADMIN)
    operator = user_factory(email="op2@example.com", role=ROLE_OPERATOR)
    op_id = operator.id

    with app.app_context():
        op = User.query.get(op_id)
        token_obj, _ = create_password_reset_token(user=op, lifetime_minutes=30)
        token_id = token_obj.id

    client.post(f"/auth/users/{op_id}/delete", follow_redirects=True)

    with app.app_context():
        assert PasswordResetToken.query.get(token_id) is None


def test_password_reset_is_unavailable_before_admin(client):
    response = client.get("/auth/forgot-password")

    assert response.status_code == 302
    assert "/auth/setup" in response.headers["Location"]


def test_password_reset_flow_after_admin_exists(client, user_factory):
    user_factory(email="admin@example.com", role=ROLE_ADMIN, password="OldPassword123!")

    response = client.post(
        "/auth/forgot-password",
        data={"email": "admin@example.com"},
        follow_redirects=True,
    )
    body = response.get_data(as_text=True)

    assert "Enlace de recuperaci" in body
    token_start = body.split("/auth/reset-password/")[1].split('"')[0]
    token = token_start.replace("amp;", "")

    response = client.post(
        f"/auth/reset-password/{token}",
        data={
            "password": "NewPassword123!",
            "password_confirm": "NewPassword123!",
        },
        follow_redirects=True,
    )
    assert "Iniciar sesi" in response.get_data(as_text=True)

    response = client.post(
        "/auth/login",
        data={"email": "admin@example.com", "password": "NewPassword123!"},
        follow_redirects=True,
    )
    assert "Overview" in response.get_data(as_text=True)


# ── Política de contraseñas ───────────────────────────────────────────────────

class TestPasswordPolicy:
    """Tests unitarios de password_policy.py — sin contexto Flask."""

    VALID = "Secure@Pass9!"   # 12 chars, mayús, minús, dígito, símbolo

    def test_valid_password_accepted(self):
        assert is_valid_password(self.VALID) is True
        assert password_errors(self.VALID) == []

    def test_too_short_rejected(self):
        # 11 chars, tiene todo lo demás
        short = "Secure@Pa9!"
        errors = password_errors(short)
        assert any("12" in e for e in errors)

    def test_no_uppercase_rejected(self):
        pw = "secure@pass9!"
        errors = password_errors(pw)
        assert any("mayúscula" in e.lower() for e in errors)

    def test_no_lowercase_rejected(self):
        pw = "SECURE@PASS9!"
        errors = password_errors(pw)
        assert any("minúscula" in e.lower() for e in errors)

    def test_no_digit_rejected(self):
        pw = "Secure@PassAB!"
        errors = password_errors(pw)
        assert any("número" in e.lower() for e in errors)

    def test_no_symbol_rejected(self):
        pw = "SecurePass9ABC"
        errors = password_errors(pw)
        assert any("símbolo" in e.lower() for e in errors)

    @pytest.mark.parametrize("pw,missing_count", [
        ("short",          4),   # falta longitud, mayús, dígito, símbolo (tiene minús)
        ("onlylowercase1", 2),   # falta mayús + símbolo
    ])
    def test_multiple_failures(self, pw, missing_count):
        assert len(password_errors(pw)) == missing_count


class TestPasswordPolicyRoutes:
    """Tests de integración: las rutas rechazan contraseñas débiles."""

    # Contraseña que NO cumple la política (sin símbolo, sin mayúscula)
    WEAK = "weaktooweakk1"

    def test_create_user_rejects_weak_password(self, client, login_as):
        login_as(ROLE_ADMIN)

        response = client.post(
            "/auth/users",
            data={
                "name": "Victim",
                "email": "victim@example.com",
                "role": ROLE_READER,
                "password": self.WEAK,
                "password_confirm": self.WEAK,
            },
            follow_redirects=True,
        )

        assert response.status_code == 200
        # El usuario NO debe haberse creado
        assert User.query.filter_by(email="victim@example.com").first() is None
        # El flash de error debe mencionar la política
        assert "no cumple" in response.get_data(as_text=True).lower()

    def test_reset_password_rejects_weak_password(self, client, user_factory):
        user_factory(email="reset@example.com", role=ROLE_ADMIN, password="OldPassword123!")

        # Solicitar reset y obtener token
        response = client.post(
            "/auth/forgot-password",
            data={"email": "reset@example.com"},
            follow_redirects=True,
        )
        body = response.get_data(as_text=True)
        token_start = body.split("/auth/reset-password/")[1].split('"')[0]
        token = token_start.replace("amp;", "")

        # Intentar fijar contraseña débil
        response = client.post(
            f"/auth/reset-password/{token}",
            data={"password": self.WEAK, "password_confirm": self.WEAK},
            follow_redirects=True,
        )

        # Debe rebotar a la pantalla de reset con mensaje de error
        assert "no cumple" in response.get_data(as_text=True).lower()
        # La contraseña del usuario no debe haber cambiado
        from app.models import User as U
        u = U.query.filter_by(email="reset@example.com").first()
        assert u.check_password("OldPassword123!")

    def test_create_user_accepts_strong_password(self, client, login_as):
        login_as(ROLE_ADMIN)

        response = client.post(
            "/auth/users",
            data={
                "name": "Strong User",
                "email": "strong@example.com",
                "role": ROLE_READER,
                "password": "Secure@Pass9!",
                "password_confirm": "Secure@Pass9!",
            },
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert User.query.filter_by(email="strong@example.com").first() is not None
