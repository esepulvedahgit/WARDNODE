"""Tests para la página de documentación del Audit Log."""
import pytest
from app.models import ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER


def test_audit_docs_renders(client, login_as):
    login_as()
    r = client.get("/audit/docs")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Índice" in body
    for anchor in ("vision-general", "que-registra", "campos", "export", "referencia"):
        assert f'id="{anchor}"' in body
        assert f'href="#{anchor}"' in body


def test_audit_docs_denied_operator(client, login_as):
    login_as(role=ROLE_OPERATOR)
    r = client.get("/audit/docs")
    assert r.status_code in (302, 403)
