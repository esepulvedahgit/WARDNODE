# WardNode — Estrategia de testing

## Stack

- **pytest** — runner y fixtures
- **SQLite en memoria** (`sqlite:///:memory:`) — base de datos aislada por test
- **TestConfig** — CSRF desactivado, rate limiting desactivado
- **pytest-cov** — cobertura de código
- Sin Docker ni servicios externos en tests

---

## Comandos

```bash
# Instalar dependencias de desarrollo
pip install -r requirements-dev.txt

# Todos los tests
pytest

# Con cobertura
pytest --cov=app --cov-report=term-missing

# Un módulo específico
pytest tests/test_proxy.py

# Filtrar por nombre
pytest -k "test_wf"

# Verbose
pytest -v
```

---

## Fixtures clave (`tests/conftest.py`)

| Fixture | Scope | Descripción |
|---------|-------|-------------|
| `app` | function | Crea Flask app con TestConfig, inicializa DB en memoria, limpia al terminar. El app context está activo durante todo el test. |
| `client` | function | `app.test_client()` para hacer requests HTTP |
| `user_factory` | function | Crea `User(email, role, password)` sin iniciar sesión |
| `login_as` | function | `login_as(role=ROLE_ADMIN)` crea usuario y hace POST a `/auth/login`. Acepta también `email=` y `password=`. |

### Patrones de uso

```python
# Login como admin (default)
login_as()

# Login como operador (crea bootstrap admin automáticamente)
login_as(role=ROLE_OPERATOR)

# Login con email específico (útil cuando un test necesita múltiples usuarios)
login_as(email="otro@example.com")

# Crear usuario sin sesión (para verificar roles sin hacer login)
user = user_factory(email="reader@example.com", role=ROLE_READER)
```

---

## Niveles de test

### Unit — validadores puros

Sin app context, sin fixtures de DB. Importan y llaman funciones directamente.

```python
# tests/test_security.py
def test_custom_rule_rejects_single_quotes():
    from app.proxy.custom_rules import validate_custom_rule
    ok, err = validate_custom_rule("SecRule ARGS '@contains it\\'s' ...")
    assert not ok
```

### Integration — routes con dependencias mockeadas

Usan `app` + `client` + `login_as`. La DB es real (SQLite en memoria). Las dependencias externas (Docker, Unix socket, subprocess) se mockean con `monkeypatch`.

```python
# Ejemplo: test de módulo WF
def test_wf_allow_port_valid(client, login_as, monkeypatch):
    login_as()
    AppConfig.set("module_wf_enabled", "1")
    calls = []

    def fake_cmd(action, **kwargs):
        calls.append({"action": action, **kwargs})
        return {"ok": True, "output": "Rule added"}

    monkeypatch.setattr("app.modules.routes.send_command", fake_cmd)
    response = client.post("/modules/wf/allow", data={"type": "port", "port": "80", "proto": "tcp"})

    assert response.status_code == 200
    assert calls[0]["action"] == "allow_port"
```

### E2E — fuera de scope de pytest

Requiere `docker compose up` completo. Se realiza manualmente:
1. Levantar el stack de desarrollo
2. Navegar al panel
3. Probar flujos de usuario críticos (crear sitio, activar WAF, configurar módulos)

---

## Patrones de mocking

### Docker SDK

```python
from types import SimpleNamespace

class FakeContainers:
    def get(self, name):
        return SimpleNamespace(status="running")

fake_docker = SimpleNamespace(
    from_env=lambda: SimpleNamespace(containers=FakeContainers()),
    errors=SimpleNamespace(NotFound=Exception),
)
monkeypatch.setitem(sys.modules, "docker", fake_docker)
```

### subprocess

```python
def fake_run(cmd, **kwargs):
    state["cmd"] = cmd
    return subprocess.CompletedProcess(cmd, 0, "", "")

monkeypatch.setattr(subprocess, "run", fake_run)
```

### send_command (socket WF/CS)

`send_command` se importa por nombre en `routes.py`, por lo que hay que parchear el nombre en el módulo que lo usa:

```python
monkeypatch.setattr("app.modules.routes.send_command", fake_fn)
```

### Funciones internas de routes

```python
monkeypatch.setattr("app.modules.routes._inject_obs_nginx_conf", lambda c: True)
monkeypatch.setattr("app.proxy.services.render_nginx_configs", lambda: [])
monkeypatch.setattr("app.proxy.geoip_blocklist.reload_nginx", lambda: (True, ""))
```

---

## Convenciones de RBAC

Los tests de RBAC verifican que rutas admin no sean accesibles por otros roles:

```python
def test_wf_requires_admin_role(client, login_as, monkeypatch):
    login_as(role=ROLE_OPERATOR)   # crea bootstrap admin + login como operator
    response = client.post("/modules/wf/status")
    assert response.status_code == 403
```

`@roles_required(ROLE_ADMIN)` llama a `abort(403)` para roles no autorizados.

---

## Cobertura actual

| Módulo | Archivos de test |
|--------|-----------------|
| Auth (login, TOTP, reset) | `test_auth.py` |
| Rutas principales | `test_main.py` |
| Proxy / WAF / Nginx / GeoIP | `test_proxy.py` |
| Módulos WF | `test_modules_wf.py` |
| Módulos CS | `test_modules_cs.py` |
| Módulos OBS + SYS | `test_modules.py` |
| Validadores (rules, headers, nginx extra) | `test_security.py` |
| Pipeline de ingesta ModSecurity | `test_proxy.py` (sección ingest) |
