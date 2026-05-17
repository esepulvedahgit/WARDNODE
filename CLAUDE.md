# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**WardNode** is a Flask-based management console for a Nginx + ModSecurity + OWASP CRS reverse proxy stack. The console lets operators configure WAF rules, traffic policies, security headers, and TLS per protected site. All configuration is written to disk as Nginx config files; the proxy reads them after reload. An optional modules system extends the console with host-level management capabilities (e.g. UFW firewall control).

## Commands

```bash
# Install dependencies
python -m venv .venv && source .venv/Scripts/activate   # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Database
flask db upgrade          # Apply migrations (run after clone or after migrate)
flask db migrate -m "…"   # Generate migration after model changes
flask init-db             # create_all() + seed default CRS rule categories

# Development server
flask run                 # http://localhost:5000

# Tests
pytest                    # All tests
pytest tests/test_proxy.py  # Single module
pytest -k "test_name"    # Single test
pytest --cov=app          # With coverage

# Docker (full stack)
docker compose up --build   # console + proxy (nginx+modsec) + db (postgres) + optional certbot
docker compose restart proxy  # Required after generating new Nginx configs
```

**Production-only CLI commands** (used in `docker-compose.vps.yml` entrypoint):
- `flask db-setup` — smart init: `create_all` + stamp on fresh DB, or `flask db upgrade` on existing.
- `flask ensure-geoip` — downloads GeoLite2-Country from MaxMind if credentials are configured.

## Architecture

### Two-container split

The **Flask console** (port 5000) is purely a management plane — it never handles proxied traffic. It writes Nginx `.conf` files to `generated/nginx/` (mounted as read-only into the proxy container). The **proxy container** (`owasp/modsecurity-crs:nginx`) reads those files and protects upstream apps.

### Config generation pipeline

Nginx configs are regenerated automatically after every route that modifies proxy-relevant settings, via `_apply_nginx()` in `proxy/routes.py` (calls `render_nginx_configs()` + `reload_nginx()`, fails silently in dev without Docker). Manual trigger: `POST /proxy/render-configs`.

- `generated/nginx/00-zones.conf` — global `limit_req_zone` / `limit_conn_zone` declarations
- `generated/nginx/site-{domain}.conf` — per-site server block with WAF directives, headers, custom rules, rate limits, and TLS

The Nginx template at `proxy/conf.d/generated.conf.template` bootstraps the proxy; per-site files are `include`-d from there.

### Blueprint layout

| Blueprint | Prefix | Purpose |
|-----------|--------|---------|
| `auth` | `/auth/` | Login, setup, user CRUD, password reset |
| `main` | `/` | Root redirect, `/status` JSON |
| `proxy` | `/proxy/` | All WAF management routes |
| `modules` | `/modules/` | Optional host-management modules (admin only) |

### Models and relationships

`Site` is the central model. All WAF config hangs off it:
- `Site` → `TrafficPolicy` (1:1) — rate/connection limiting
- `Site` → `SecurityHeader` (1:N) — per-site HTTP security headers
- `Site` → `CustomModSecurityRule` (1:N) — validated SecRule/SecAction snippets
- `Site` → `NginxExtraConfig` (1:1) — raw server/location snippets (validated)
- `Site` → `SiteRuleSetting` (1:N) → `RuleCategory` — which OWASP CRS categories are active
- `Site` → `AttackEvent` (1:N) — ModSecurity events (ingestion pending)

`AppConfig` is a generic key-value store (`app_config` table) used for all app-wide settings (module toggles, MaxMind credentials, SMTP config). Sensitive values are stored encrypted (`encrypted=True` column); read them back with `decrypt_secret()` from `app/encryption.py`. Requires `WARDNODE_SECRET_KEY` in env.

Module state is injected into every template via a context processor in `app/__init__.py`:
```python
{"module_wf_enabled": AppConfig.get("module_wf_enabled") == "1"}
```

### Modules system — WardNode WF

Optional modules are catalogued in `modules/routes.py:MODULES` and toggled via `AppConfig`. Each module has a `config_key` (e.g. `module_wf_enabled`).

**WardNode WF** provides UFW firewall management without SSH by running a privileged daemon on the host:

```
Flask container  ──Unix socket──►  wardnode-wf-agent.py (host daemon)
  modules/socket_client.py           sudoers: NOPASSWD /usr/sbin/ufw
  send_command("allow_port", ...)    systemd: wardnode-wf.service
```

Protocol: 4-byte big-endian length prefix + JSON payload. The socket is bind-mounted from `/run/wardnode/wardnode-wf.sock` on the host to `/app/sockets/wardnode-wf.sock` in the container (path controlled by `WF_SOCKET_PATH` env var).

Input validation is **dual-layer**: Flask validates in `socket_client.py` before sending; the agent re-validates every field independently (never trust the caller).

The **host agent** (`host-agent/wardnode-wf-agent.py`) is installed once via `host-agent/install.sh` (run as root). Install can be triggered from the UI via SSH (paramiko) — Flask connects to `host.docker.internal` using the admin-provided private key, SFTPs the agent files, runs `install.sh`, and adds the SSH user to the `wardnode-wf` group. `host.docker.internal` requires `extra_hosts: host-gateway` in `docker-compose.vps.yml`.

**UFW initialization gate**: before allowing rule management, the agent must have `default deny incoming` set. `wf_status` calls `check_defaults` and returns `initialized: bool`. The UI blocks Permitir/Bloquear panels until the admin completes the one-time init step.

### Frontend stack

Jinja2 templates + **HTMX** for partial page updates + **Alpine.js** for local state. CSRF is handled globally by Flask-WTF; `app/static/js/app.js` injects the `X-CSRFToken` header on every HTMX mutating request (non-GET).

**Alpine.js notes**: nested `x-data` components inherit parent scope (child can read `initialized`, `agentOk` from grandparent `wfPanel()`). For cross-component events use `$dispatch` + `@event-name.window` listeners — never `Alpine.$data()`.

### Security controls worth knowing

- `@roles_required(ROLE_ADMIN, ...)` decorator in `auth/decorators.py` gates mutations.
- Flask-Limiter is applied to login (5/hour), setup, and password reset routes.
- Custom ModSec rule text is validated in `proxy/custom_rules.py` — no single quotes, no `include`/`exec:`/`lua:`/`ctl:ruleEngine=Off`, balanced quotes, ID in 1,000,000–1,999,999 range.
- Nginx extra directives validated in `proxy/nginx_extra.py` — blacklisted keywords, optional `nginx -t` dry-run.
- Security headers validated in `proxy/security_headers.py` — header name and value sanitization.
- Socket commands are whitelisted in `ACTIONS` set in the agent; all args are re-validated with regex before any `subprocess.run` call (never `shell=True`).

## Environment Variables

| Variable | Default | Notes |
|----------|---------|-------|
| `SECRET_KEY` | `change-me` | Must be set in production |
| `WARDNODE_SECRET_KEY` | `""` | Required to store encrypted secrets (MaxMind, SMTP creds) |
| `DATABASE_URL` | `sqlite:///app.db` | Docker uses PostgreSQL |
| `PROXY_CONFIG_DIR` | `generated/nginx` | Where Flask writes Nginx configs |
| `WF_SOCKET_PATH` | `/app/sockets/wardnode-wf.sock` | Unix socket path for WardNode WF agent |
| `NGINX_CONTAINER_NAME` | `wardnode-proxy` | Container name for Docker SDK calls (Let's Encrypt) |
| `SESSION_COOKIE_SECURE` | `false` | Set `true` when behind HTTPS |
| `RATELIMIT_STORAGE_URI` | `memory://` | Use `redis://` for multi-process |
| `PASSWORD_RESET_SHOW_TOKEN` | `false` | Dev only — never enable in prod |
| `PASSWORD_RESET_TOKEN_MINUTES` | `30` | Reset token expiry |

Copy `.env.example` to `.env` before first run.

## Testing

`tests/conftest.py` provides `app`, `client`, and `login_as` fixtures. `TestConfig` disables CSRF and rate limiting and uses in-memory SQLite. Tests assert Nginx config output directly (string matching against generated file content) and validate RBAC denials.
