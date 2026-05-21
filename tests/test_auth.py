from app.models import ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER, User


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
    assert "Iniciar sesion" in response.get_data(as_text=True)

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

    assert "Enlace de recuperacion temporal" in body
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
    assert "Iniciar sesion" in response.get_data(as_text=True)

    response = client.post(
        "/auth/login",
        data={"email": "admin@example.com", "password": "NewPassword123!"},
        follow_redirects=True,
    )
    assert "Overview" in response.get_data(as_text=True)
