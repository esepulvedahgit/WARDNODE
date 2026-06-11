# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**WardNode** is a Flask-based management console for a Nginx + ModSecurity + OWASP CRS reverse proxy stack. The console lets operators configure WAF rules, traffic policies, security headers, and TLS per protected site. All configuration is written to disk as Nginx config files; the proxy reads them after reload. An optional modules system extends the console with host-level management capabilities (UFW firewall, CrowdSec IDS/IPS, and observability).

## Commands

```bash
# Install dependencies (Python 3.12+ required)
python -m venv .venv && source .venv/bin/activate
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
docker compose up --build          # console + proxy + db
docker compose --profile obs up    # also starts Alloy + Loki + Prometheus + Grafana
docker compose restart proxy       # Required after generating new Nginx configs
```

**Production-only CLI commands** (used in `docker-compose.vps.yml` entrypoint):
- `flask db-setup` — smart init: `create_all` + stamp on fresh DB, or `flask db upgrade` on existing.
- `flask ensure-geoip` — downloads GeoLite2-Country from MaxMind if credentials are configured.

## Architecture

### Two-container split

The **Flask console** (port 5000) is purely a management plane — it never handles proxied traffic. It writes Nginx `.conf` files to `generated/nginx/` (mounted as read-only into the proxy container). The **proxy container** (`owasp/modsecurity-crs:nginx`) reads those files and protects upstream apps. The proxy image is custom-built in `proxy/Dockerfile` (adds ngx_http_geoip2_module) and ships with `proxy/modsecurity/modsecurity-override.conf` baked in (enables JSON audit logs via YAJL).

### Config generation pipeline

Nginx configs are regenerated automatically after every route that modifies proxy-relevant settings, via `_apply_nginx()` in `proxy/routes.py` (calls `render_nginx_configs()` + `reload_nginx()`, fails silently in dev without Docker). Manual trigger: `POST /proxy/render-configs`.

- `generated/nginx/00-geoip.conf` — GeoIP2 database load + `$geo_blocked` map for country blocklist
- `generated/nginx/00-zones.conf` — global `limit_req_zone` / `limit_conn_zone` declarations
- `generated/nginx/site-{domain}.conf` — per-site server block with WAF directives, headers, custom rules, rate limits, and TLS

The `proxy/conf.d/generated.conf` template bootstraps the proxy with a single `include /etc/nginx/generated/*.conf;`. The log format `json_combined` is defined in `observability/nginx/log-format.conf` (mounted as `00-log-format.conf`), which must load before any server block; the numeric prefix guarantees this.

### Blueprint layout

| Blueprint | Prefix | Purpose |
|-----------|--------|---------|
| `auth` | `/auth/` | Login, setup, user CRUD, password reset, TOTP enrollment |
| `main` | `/` | Root redirect, `/status` JSON |
| `proxy` | `/proxy/` | All WAF management routes |
| `modules` | `/modules/` | Optional host-management modules (admin only) |
| `audit` | `/audit/` | Audit log dashboard (KPI cards, timeline chart, CSV export) — admin only |
| `soc` | `/soc/` | SOC: incident correlation, LLM analysis, alerts, ML anomaly scoring — admin only |
| `backup` | `/backup/` | Disaster-recovery backups: AES-256 zip (pg_dump + TLS certs + WF host state), daily scheduler, email delivery, UI/CLI restore — admin only |

### Models and relationships

`Site` is the central model. All WAF config hangs off it:
- `Site` → `TrafficPolicy` (1:1) — rate/connection limiting
- `Site` → `SecurityHeader` (1:N) — per-site HTTP security headers
- `Site` → `CustomModSecurityRule` (1:N) — validated SecRule/SecAction snippets
- `Site` → `NginxExtraConfig` (1:1) — raw server/location snippets (validated)
- `Site` → `BotProtectionConfig` (1:1) — bot challenge gate (cookie `wn_bot=ward_cleared_v1`). When enabled, unknown clients are redirected to `/_wn_challenge/` before reaching the upstream. The challenge HTML + JS is embedded in `services.py:_build_challenge_html()`.
- `Site` → `SiteRuleSetting` (1:N) → `RuleCategory` — which OWASP CRS categories are active
- `Site` → `AttackEvent` (1:N) — ModSecurity block/detect events populated by the ingest thread

`AuditLog` records operator actions (config changes, logins, etc.) and system events. Write entries with `log_audit()` from `app/audit/helpers.py` — it never raises exceptions and uses a SQLAlchemy `SAVEPOINT` to avoid committing the caller's pending transaction. Fields: `actor_email`, `action`, `resource_type`, `resource_name`, `severity` (`info`/`warning`/`error`/`critical`), `status` (`success`/`failure`), `detail` (JSON string).

`AppConfig` is a generic key-value store (`app_config` table) used for all app-wide settings (module toggles, MaxMind credentials, SMTP config). Sensitive values are stored encrypted (`encrypted=True` column); read them back with `decrypt_secret()` from `app/encryption.py`. Requires `WARDNODE_SECRET_KEY` in env.

`GeoBlocklistEntry` stores ISO country codes to block at the Nginx level. `proxy/geoip_blocklist.py` regenerates `00-geoip.conf` and reloads Nginx immediately (separate from the full `render_nginx_configs()` cycle).

### AttackEvent ingest thread

`proxy/ingest.py:start_ingest_thread()` is called at app startup (`app/__init__.py`). It spawns a daemon thread (`modsec-ingest`) that streams Docker logs from the proxy container via the Docker SDK (`docker.from_env()`). The OWASP CRS nginx image always writes ModSecurity JSON audit events to container stdout — never to file — so the thread reads them from there. Container name is controlled by `WARDNODE_PROXY_CONTAINER` (default `wardnode-proxy`). Each JSON line is parsed into an `AttackEvent` row; duplicate `transaction_id` values are silently discarded via `IntegrityError` rollback. In dev without Docker the thread is not started (Docker ping fails gracefully).

### TOTP two-factor authentication

`User` has `totp_enabled` (bool) and `totp_secret` (encrypted via `encrypt_secret()`). When TOTP is active the login flow adds an intermediate step: session key `_totp_user_id` holds the pending user ID until the TOTP code is verified. Enrollment stores the pending secret in `session["_totp_pending"]` until the user confirms with a valid code.

Module state is injected into every template via a context processor in `app/__init__.py`:
```python
{"module_wf_enabled": ..., "module_cs_enabled": ..., "module_obs_enabled": ..., "module_soc_enabled": ...}
```

### SOC module

The `soc` blueprint (gated by `module_soc_enabled` + admin role) correlates `AttackEvent` rows into `SocIncident`s. Pipeline (all in `app/soc/`):

1. **Worker** (`worker.py`) — daemon thread (`soc-worker`) started at app startup; runs `run_detection_cycle()` every `soc_worker_interval_min` minutes. Under gunicorn multi-worker, a PostgreSQL advisory lock (`pg_try_advisory_lock`, key 815001) ensures a single process runs the cycle and ML retraining.
2. **Detection** (`detect.py`) — SQL aggregation per source IP within a time window (volume, category diversity, path fan-out, block ratio, method/status diversity) → deterministic heuristic score 0–100 → severity. Dedupe: an open incident from the same IP within 1h is updated, not duplicated.
3. **Enrichment** (`enrich.py`) — AbuseIPDB reputation (cached in `ThreatIntelCache`, TTL 24h, capped at `MAX_ENRICH_PER_CYCLE=25` calls/cycle, only public IPs) + static CRS→MITRE mapping whose names/tactics are refreshed from the local CTI table.
4. **MITRE CTI** (`mitre_cti.py`) — downloads the official `enterprise-attack.json` (~50 MB, capped at 100 MB, manual trigger `POST /soc/mitre-sync` or auto-once if table empty) into `MitreAttackTechnique`. Used to (a) authorize names/tactics in `map_mitre`, (b) reject hallucinated technique IDs from the LLM (`schema._coerce_mitre`), (c) inject an authorized-reference section into the LLM prompt.
5. **LLM analysis** (`llm/`) — multi-provider via pure httpx (openrouter/anthropic/openai/deepseek/gemini), router with fallback, 2 MB response cap, API keys Fernet-encrypted in `AppConfig`. Guards: `soc_data_optin == "1"`, severity threshold, `MAX_LLM_ANALYSES_PER_CYCLE=5`. Only aggregated metadata is sent — never request bodies. Output normalized by `schema.normalize_llm_output()` (tolerant, never raises).
6. **Alerts** (`alerts.py`) — email (reuses global SMTP config via `app/email.py:send_soc_alert_email`) + Telegram (`soc_alert_telegram_token` encrypted; chat_id regex-validated). Severity threshold + per-IP cooldown via `SocIncident.alerted_at`. The bot token never appears in logs or audit entries.
7. **ML scoring** (`ml.py`) — IsolationForest (scikit-learn) trained on hourly per-IP aggregates of the last 14 days (min 100 samples, max 50k rows), serialized with joblib into `SocMlModel` (DB blob → multi-worker consistent; never load external blobs — pickle). The heuristic score is always the severity floor; ML can only raise it (`max(score, ml_score)`). Opt-in via `soc_ml_enabled`; retrain every `soc_ml_retrain_hours` (default 24) inside the advisory lock, or manually via `POST /soc/ml-train`.

UI: dashboard (`/soc/`), bitácora with filters + CSV export, incident detail (heuristic/ML/AbuseIPDB scores, MITRE chips with tactics, LLM analysis blocks), config (`/soc/config` — providers, keys, opt-in, alerts, ML, MITRE sync), notification bell (`/soc/notifications/count`).

### Backup module

The `backup` blueprint (admin only, toggle `module_backup_enabled`) produces disaster-recovery backups as AES-256 zips (pyzipper). All logic lives in `app/backup/`:

- **Contents**: `db/wardnode.pgdump` (`pg_dump -Fc` exec'd inside the `wardnode-db` container via Docker SDK — password via `PGPASSWORD` env, never argv), `tls/letsencrypt.tar.gz` (read from the `letsencrypt` volume mounted ro into console, Docker SDK `get_archive` fallback), `host/ufw-rules.txt` + `host/protected_ports.json` (via WF socket, soft-fail), `manifest.json` (format version, alembic head, SHA-256 checksums, included/skipped components) and `README-RESTORE.md`. The zip **never** contains `WARDNODE_SECRET_KEY` or `.env` — that key must be kept separately or encrypted secrets in the dump are unrecoverable.
- **Scheduler** (`worker.py`): daemon thread cloned from the SOC worker, advisory lock **815002**, daily at `backup_hour` (UTC). `is_backup_due()` is a pure function. Outcome persisted in `backup_last_run_at`/`backup_last_status` on success *and* failure. Email via `app/email.py:send_email()` (attachments support): attaches the zip if under `backup_email_max_mb` (default 20), otherwise notification-only; failure alert email on error.
- **Restore**: CLI `flask backup-restore <zip>` (prompts password, validates manifest + checksums, `pg_restore --clean --if-exists --no-owner`, applies pending migrations, regenerates nginx configs) or UI upload gated by **re-authentication** (admin password + TOTP if enabled) + typed `RESTAURAR` confirmation. `validate_backup_zip()` enforces path whitelist, anti zip-bomb (ratio/size caps) and blocks dumps from newer alembic heads. TLS/WF state are documented manual steps, never auto-applied.
- **Storage**: `WARDNODE_BACKUP_DIR` (default `/app/data/backups`, named volume `backups`). Filenames match `wardnode-backup-YYYYMMDD-HHMMSS.zip` — the regex doubles as path-traversal guard in download/delete. Retention via `backup_retention` (prune keeps newest N). Atomic writes (`.zip.part` + `os.replace`).
- CLI: `flask backup-create`, `flask backup-restore`, `flask backup-prune [--keep N]`.

### Modules system

Optional modules are catalogued in `modules/routes.py:MODULES` and toggled via `AppConfig`. There are four modules (WF, CS, OBS below — the SOC module is described in its own section above):

**WardNode WF** — UFW firewall management without SSH by running a privileged daemon on the host:

```
Flask container  ──Unix socket──►  wardnode-wf-agent.py (host daemon)
  modules/socket_client.py           systemd service runs as root:wardnode
  send_command("allow_port", ...)    systemd: wardnode-wf.service
```

Protocol: 4-byte big-endian length prefix + JSON payload. The socket is bind-mounted from `/run/wardnode/wardnode-wf.sock` on the host to `/app/sockets/wardnode-wf.sock` in the container (path controlled by `WF_SOCKET_PATH` env var).

Input validation is **dual-layer**: Flask validates in `socket_client.py` before sending; the agent re-validates every field independently (never trust the caller). Socket commands are whitelisted in `ACTIONS` set in the agent; all args re-validated with regex before any `subprocess.run` call (never `shell=True`).

The host agent (`host-agent/wardnode-wf-agent.py`) is installed via `host-agent/install.sh` (run as root). Install can be triggered from the UI via SSH (paramiko) — Flask connects to `host.docker.internal` using the admin-provided private key. `host.docker.internal` requires `extra_hosts: host-gateway` in `docker-compose.vps.yml`. The current systemd unit runs the agent as `root` with group `wardnode`; access control is enforced by the Unix socket path and the allowlisted JSON protocol.

**UFW initialization gate**: `wf_status` calls `check_defaults` and returns `initialized: bool`. The UI blocks Permitir/Bloquear panels until the admin completes the one-time init step (`default deny incoming`).

**WardNode CS** — CrowdSec IDS/IPS. CrowdSec is installed by `host-agent/install.sh` and left disabled until the module is enabled. Post-install, the Flask UI drives status, decisions, ban/unban, and service start/stop through the same WF Unix socket; the agent calls `cscli` or `/opt/wardnode/wardnode-cs-control.sh`. Requires WF to be active first (CS bouncer acts via UFW).

**WardNode OBS** — Observability stack activated via the `obs` Docker Compose profile. Stack: Grafana Alloy (collector) → Loki (logs) + Prometheus (metrics) → Grafana. Alloy replaces Fluent Bit for OBS collection and embeds node-exporter functionality via `prometheus.exporter.unix`. Grafana is served at `/obs/` through an `obs.conf` file injected into the running proxy container by `modules/routes.py:_inject_obs_nginx_conf()`. In production, observability configs are copied from the console image into named volumes before the OBS containers start.

### Frontend stack

Jinja2 templates + **HTMX** for partial page updates + **Alpine.js** for local state. CSRF is handled globally by Flask-WTF; `app/static/js/app.js` injects the `X-CSRFToken` header on every HTMX mutating request (non-GET).

**Alpine.js notes**: nested `x-data` components inherit parent scope (child can read `initialized`, `agentOk` from grandparent `wfPanel()`). For cross-component events use `$dispatch` + `@event-name.window` listeners — never `Alpine.$data()`.

### Security controls worth knowing

- `@roles_required(ROLE_ADMIN, ...)` decorator in `auth/decorators.py` gates mutations.
- Flask-Limiter is applied to login (5/hour), setup, and password reset routes.
- Custom ModSec rule text is validated in `proxy/custom_rules.py` — no single quotes, no `include`/`exec:`/`lua:`/`ctl:ruleEngine=Off`, balanced quotes, ID in 1,000,000–1,999,999 range.
- Nginx extra directives validated in `proxy/nginx_extra.py` — blacklisted keywords, optional `nginx -t` dry-run.
- Security headers validated in `proxy/security_headers.py` — header name and value sanitization.

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
| `WARDNODE_PROXY_CONTAINER` | `wardnode-proxy` | Docker container name to stream ModSecurity logs from |
| `WARDNODE_BACKUP_DIR` | `/app/data/backups` | Where encrypted backup zips are stored (named volume `backups`) |
| `WARDNODE_DB_CONTAINER` | `wardnode-db` | Container name for pg_dump/pg_restore via Docker SDK |

Copy `.env.example` to `.env` before first run.

## Testing

`tests/conftest.py` provides `app`, `client`, `user_factory`, and `login_as` fixtures. `TestConfig` disables CSRF and rate limiting and uses in-memory SQLite.

- `login_as(role=ROLE_ADMIN)` logs in a user and returns the `User` object. Non-admin roles auto-create a bootstrap admin first.
- Tests assert Nginx config output directly (string matching against generated file content using `tmp_path`) and validate RBAC denials.
- `test_security.py` exercises the validation logic in `custom_rules.py`, `nginx_extra.py`, and `security_headers.py` directly.
