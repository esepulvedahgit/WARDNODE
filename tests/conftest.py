import pytest

from app import create_app
from app.config import TestConfig
from app.extensions import db
from app.models import ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER, User


@pytest.fixture()
def app():
    app = create_app(TestConfig)

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def user_factory(app):
    def factory(email="admin@example.com", role=ROLE_ADMIN, password="ChangeMe12345!"):
        user = User(email=email, name=email.split("@")[0], role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user

    return factory


@pytest.fixture()
def login_as(client, user_factory):
    def login(role=ROLE_ADMIN, email=None, password="ChangeMe12345!"):
        if role != ROLE_ADMIN:
            user_factory(email="admin-bootstrap@example.com", role=ROLE_ADMIN)
        user = user_factory(
            email=email or f"{role}@example.com",
            role=role,
            password=password,
        )
        client.post(
            "/auth/login",
            data={"email": user.email, "password": password},
            follow_redirects=True,
        )
        return user

    return login
