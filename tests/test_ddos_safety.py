"""Tests para app/ddos/safety.py — guardas de ban/unban manual CrowdSec."""
import pytest

from app import create_app
from app.config import TestConfig


@pytest.fixture
def app_ctx():
    """Contexto Flask mínimo para que is_ban_safe() pueda acceder a AppConfig."""
    app = create_app(TestConfig)
    with app.app_context():
        from app.extensions import db
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


# ── Helpers ──────────────────────────────────────────────────────────


def _safe(ip: str, req_ip: str = "10.0.0.99") -> tuple:
    from app.ddos.safety import is_ban_safe
    return is_ban_safe(ip, req_ip)


# ── Guardas de formato ────────────────────────────────────────────────


def test_rejects_cidr(app_ctx):
    ok, reason = _safe("1.2.3.0/24")
    assert not ok
    assert "inválida" in reason.lower() or "cidr" in reason.lower()


def test_rejects_garbage(app_ctx):
    ok, reason = _safe("not-an-ip")
    assert not ok


# ── Guardia 1: IP del admin actual ───────────────────────────────────


def test_rejects_own_ip(app_ctx):
    ok, reason = _safe("203.0.113.5", req_ip="203.0.113.5")
    assert not ok
    assert "propia" in reason.lower() or "propi" in reason.lower()


# ── Guardia 2: rangos privados / reservados ───────────────────────────


@pytest.mark.parametrize("ip", [
    "127.0.0.1",         # loopback
    "127.1.2.3",
    "10.0.0.1",          # RFC-1918 clase A
    "172.16.0.1",        # RFC-1918 clase B (red Docker)
    "172.30.0.5",        # subred Docker wardnode_internal
    "192.168.1.100",     # RFC-1918 clase C
    "169.254.0.1",       # link-local
    "::1",               # loopback IPv6
    "0.0.0.0",           # unspecified
])
def test_rejects_private_ranges(app_ctx, ip):
    ok, reason = _safe(ip)
    assert not ok, f"Debería rechazar {ip} pero no lo hizo"
    assert "reservado" in reason.lower() or "privado" in reason.lower() or "rango" in reason.lower()


# ── Guardia 5: allowlist editable ─────────────────────────────────────


def test_rejects_allowlist_ip(app_ctx):
    from app.models import AppConfig
    # 8.8.8.8 y 1.1.1.1 son IPs públicas reales (no en rangos reservados de Python)
    AppConfig.set("ddos_safe_ips", "8.8.8.8,1.1.1.1")
    ok, reason = _safe("8.8.8.8")
    assert not ok
    assert "protegidas" in reason.lower() or "allowlist" in reason.lower() or "lista" in reason.lower()


def test_allowlist_partial_match_does_not_block(app_ctx):
    """Una IP distinta no se ve afectada por la allowlist."""
    from app.models import AppConfig
    AppConfig.set("ddos_safe_ips", "8.8.8.8")
    ok, _ = _safe("8.8.4.4")  # IP pública diferente
    assert ok


# ── Caso feliz: IP pública ajena ──────────────────────────────────────


def test_accepts_public_ip(app_ctx):
    from app.models import AppConfig
    AppConfig.set("ddos_safe_ips", "")  # allowlist vacía
    ok, reason = _safe("4.4.4.4", req_ip="8.8.8.8")
    assert ok, f"Debería aceptar IP pública pero rechazó: {reason}"


def test_accepts_another_public_ip(app_ctx):
    """IP pública distinta a la del admin — debe permitirse."""
    ok, reason = _safe("1.1.1.1", req_ip="8.8.8.8")
    assert ok, f"Debería aceptar 1.1.1.1 pero rechazó: {reason}"


# ── RBAC routes (smoke test — 403 sin módulo activo) ─────────────────


@pytest.fixture
def client(app_ctx):
    return app_ctx.test_client()


@pytest.fixture
def admin_client(app_ctx):
    from tests.conftest import _login_as  # reutilizar helper si existe
    return app_ctx.test_client()


def test_ddos_status_requires_module(client):
    """Sin módulo habilitado, /ddos/status debe devolver 403."""
    # No activamos el módulo — AppConfig.get("module_ddos_enabled") == None
    r = client.get("/modules/ddos/status")
    # Sin sesión, Flask-Login redirige a login; con módulo desactivado es 403.
    assert r.status_code in (302, 401, 403)


def test_ddos_ban_unauthenticated(client):
    r = client.post("/modules/ddos/ban", data={"ip": "1.2.3.4"})
    assert r.status_code in (302, 401, 403)
