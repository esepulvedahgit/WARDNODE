from app.models import ROLE_ADMIN


def test_index_redirects_to_setup_before_admin(client):
    response = client.get("/")

    assert response.status_code == 302
    assert "/auth/setup" in response.headers["Location"]


def test_status_partial_loads(client):
    response = client.get("/partials/status")

    assert response.status_code == 200
    assert "HTMX esta respondiendo" in response.get_data(as_text=True)


def test_proxy_dashboard_loads_for_authenticated_user(client, login_as):
    login_as(ROLE_ADMIN)
    response = client.get("/proxy/")

    assert response.status_code == 200
    assert "Overview" in response.get_data(as_text=True)
