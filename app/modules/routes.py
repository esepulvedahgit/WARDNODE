import io
import os
import re
import threading
import time

from flask import jsonify, make_response, redirect, render_template, request, url_for
from flask_login import current_user

from app.audit.helpers import log_audit
from app.auth.decorators import roles_required
from app.extensions import db, limiter
from app.models import AppConfig, ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER
from app.modules import bp
from app.modules.socket_client import (
    SOCKET_PATH,
    send_command,
    valid_ip,
    valid_port,
    valid_proto,
    valid_rule_num,
)

# ── Catálogo de módulos disponibles ───────────────────────────────────

MODULES = [
    {
        "id": "wf",
        "name": "WardNode WF",
        "description": "Administración del firewall UFW del host Linux sin SSH. "
                       "Permite y bloquea puertos e IPs desde el panel con aislamiento de privilegios estricto.",
        "icon": "bi-shield-fill-exclamation",
        "config_key": "module_wf_enabled",
        "endpoint": "modules.wf_index",
    },
    {
        "id": "obs",
        "name": "WardNode OBS",
        "description": "Observabilidad centralizada: logs WAF, nginx, ModSecurity y SSH "
                       "en Grafana + Loki. Accede vía SSH tunnel a localhost:3000.",
        "icon": "bi-bar-chart-line-fill",
        "config_key": "module_obs_enabled",
        "endpoint": "modules.obs_index",
    },
    {
        "id": "soc",
        "name": "WardNode SOC",
        "description": "Centro de operaciones de seguridad: correlaciona eventos WAF en "
                       "incidentes, los enriquece con threat intel y los analiza con IA.",
        "icon": "bi-robot",
        "config_key": "module_soc_enabled",
        "endpoint": "soc.index",
    },
    {
        "id": "ddos",
        "name": "WardNode CrowdSec",
        "description": "Protección SSH brute-force con CrowdSec. Detecta y banea "
                       "atacantes automáticamente vía nftables, sin interferir con UFW.",
        "icon": "bi-shield-shaded",
        "config_key": "module_ddos_enabled",
        "endpoint": "modules.ddos_index",
    },
]


# ── Helpers para bloqueo diferido del puerto 5000 ─────────────────────

def _get_console_url() -> str | None:
    """Devuelve http://<dominio> si hay un site de consola configurado."""
    from app.models import Site
    cid = AppConfig.get("console_site_id")
    if cid and cid.isdigit():
        site = db.session.get(Site, int(cid))
        if site and site.domain:
            return f"http://{site.domain}"
    return None


def _secure_port_async(delay: float = 5.0) -> None:
    """Bloquea el puerto 5000 en un thread background con delay.

    El delay garantiza que la HTTP response activa llegue al cliente antes
    de que iptables corte la conexión TCP al puerto 5000.
    """
    def _worker():
        time.sleep(delay)
        try:
            send_command("secure_console_port", timeout=15)
        except Exception:
            pass
    threading.Thread(target=_worker, daemon=True).start()


@bp.get("/")
@roles_required(ROLE_ADMIN)
def index():
    states = {m["id"]: AppConfig.get(m["config_key"]) == "1" for m in MODULES}
    return render_template("modules/index.html", modules=MODULES, states=states)


@bp.post("/<name>/toggle")
@roles_required(ROLE_ADMIN)
def toggle(name: str):
    from flask import flash
    module = next((m for m in MODULES if m["id"] == name), None)
    if module is None:
        return jsonify({"ok": False, "error": "Módulo desconocido"}), 404
    current = AppConfig.get(module["config_key"]) == "1"

    if name == "obs" and not current:
        flash("Usa el botón 'Activar' para iniciar el proceso de verificación de OBS.", "info")
        return redirect(url_for("modules.index"))

    if name == "ddos" and not current:
        flash("Usa el botón 'Activar' para iniciar el proceso de verificación de CrowdSec.", "info")
        return redirect(url_for("modules.index"))

    new_state = not current

    if name == "wf" and new_state:
        console_site_id = AppConfig.get("console_site_id")
        if not console_site_id or not console_site_id.isdigit():
            flash(
                "Debes configurar el dominio de acceso al panel "
                "(Ajustes → Acceso al panel) antes de activar el módulo WardNode WF.",
                "danger",
            )
            return redirect(url_for("modules.index"))

        AppConfig.set(module["config_key"], "1")
        log_audit("module.toggle", resource_type="module", resource_name=name,
                  detail={"enabled": True})

        # Si el agente ya está instalado, bloquear el puerto 5000 de forma diferida
        # para que este redirect llegue al cliente antes de que iptables corte TCP:5000.
        if os.path.exists(SOCKET_PATH):
            console_url = _get_console_url()
            if console_url:
                _secure_port_async(delay=5)
                flash(
                    "WardNode WF activado. El acceso por el puerto 5000 quedará bloqueado "
                    f"en segundos — continúa desde tu dominio: {console_url}",
                    "warning",
                )
                login_url = console_url + url_for("auth.login") + "?reason=port_secured"
                return redirect(login_url)

        flash("WardNode WF activado.", "success")
        return redirect(url_for("modules.index"))

    AppConfig.set(module["config_key"], "1" if new_state else "0")
    log_audit("module.toggle", resource_type="module", resource_name=name,
              detail={"enabled": new_state})
    return redirect(url_for("modules.index"))


# ── WardNode WF ───────────────────────────────────────────────────────

def _wf_required():
    """Returns None if access is allowed, otherwise a redirect response."""
    if AppConfig.get("module_wf_enabled") != "1":
        return redirect(url_for("modules.index"))
    return None


@bp.get("/wf/")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
def wf_index():
    if (r := _wf_required()):
        return r
    return render_template("modules/wf.html", socket_path=SOCKET_PATH)


_SSH_USER_RE = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")
_SSH_HOST = os.environ.get("WF_SSH_HOST", "host.docker.internal")
_GRAFANA_URL = os.environ.get("WARDNODE_GRAFANA_URL", "http://127.0.0.1:3000")
_AGENT_FILES = [
    "/app/host-agent/wardnode-wf-agent.py",
    "/app/host-agent/wardnode-wf.service",
    "/app/host-agent/wardnode-set-ipv6.sh",
    "/app/host-agent/install.sh",
]


def _make_ssh_client(ssh_host: str, ssh_port: int):
    """Devuelve (client, stored_b64, policy) con política TOFU de host key.

    Primera conexión: captura y almacena el fingerprint del host en AppConfig.
    Conexiones posteriores: verifica contra el fingerprint almacenado y rechaza
    si no coincide (posible MITM).
    """
    import base64
    import paramiko as _pm

    stored_b64 = AppConfig.get("wf_ssh_host_key")
    client = _pm.SSHClient()

    class _FirstUsePolicy(_pm.MissingHostKeyPolicy):
        captured = None

        def missing_host_key(self, c, h, k):
            self.captured = k  # Captura para persistir después del connect

    class _VerifyPolicy(_pm.MissingHostKeyPolicy):
        def missing_host_key(self, c, hostname, key):
            incoming = base64.b64encode(key.asbytes()).decode()
            if incoming != stored_b64:
                raise _pm.SSHException(
                    f"Fingerprint del host '{hostname}:{ssh_port}' no coincide con el registrado. "
                    "Si el host cambió su clave SSH, elimina 'wf_ssh_host_key' en la configuración de la app."
                )

    policy = _VerifyPolicy() if stored_b64 else _FirstUsePolicy()
    client.set_missing_host_key_policy(policy)
    return client, stored_b64, policy


def _tofu_persist(stored_b64, policy) -> None:
    """Si fue primera conexión TOFU, persiste el host key capturado en AppConfig."""
    import base64
    if stored_b64 is None and getattr(policy, "captured", None) is not None:
        AppConfig.set("wf_ssh_host_key", base64.b64encode(policy.captured.asbytes()).decode())


@bp.post("/wf/install")
@roles_required(ROLE_ADMIN)
def wf_install():
    try:
        import paramiko
    except ImportError:
        return jsonify({"ok": False, "error": "Dependencia 'paramiko' no instalada en el contenedor."}), 500

    ssh_host = _SSH_HOST
    ssh_user = "root"
    ssh_key_text = request.form.get("ssh_key", "").strip()

    if not ssh_key_text:
        try:
            ssh_key_text = AppConfig.get_secret("wf_ssh_private_key") or ""
        except Exception:
            ssh_key_text = ""
    if not ssh_key_text:
        return jsonify({"ok": False, "error": "Clave SSH requerida"}), 400

    ssh_port_raw = request.form.get("ssh_port", "").strip()
    if not ssh_port_raw:
        ssh_port_raw = AppConfig.get("wf_ssh_port") or "22"

    try:
        ssh_port = int(ssh_port_raw)
        if not (1 <= ssh_port <= 65535):
            raise ValueError
    except ValueError:
        return jsonify({"ok": False, "error": "Puerto SSH inválido"}), 400

    key = None
    for key_cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
        try:
            key = key_cls.from_private_key(io.StringIO(ssh_key_text))
            break
        except Exception:
            continue
    if key is None:
        return jsonify({"ok": False, "error": "Clave SSH inválida o formato no reconocido (RSA, Ed25519, ECDSA)"}), 400

    client, stored_b64, tofu_policy = _make_ssh_client(ssh_host, ssh_port)
    try:
        client.connect(ssh_host, port=ssh_port, username=ssh_user, pkey=key, timeout=15)
        _tofu_persist(stored_b64, tofu_policy)

        _, _so, _ = client.exec_command("sudo -n true 2>&1", timeout=10)
        if _so.channel.recv_exit_status() != 0:
            client.close()
            return jsonify({
                "ok": False,
                "error": (
                    f"El usuario '{ssh_user}' requiere contraseña para sudo. "
                    "Usa root, o un usuario con NOPASSWD en sudoers "
                    "(ej: usuario ALL=(ALL) NOPASSWD: ALL)."
                )
            }), 400

        _, mktemp_out, _ = client.exec_command("mktemp -d /tmp/wardnode_XXXXXX", timeout=10)
        mktemp_out.channel.recv_exit_status()
        tmp_dir = mktemp_out.read().decode().strip()
        if not tmp_dir or not tmp_dir.startswith("/tmp/wardnode_"):
            return jsonify({"ok": False, "error": "No se pudo crear directorio temporal seguro en el host"}), 500

        sftp = client.open_sftp()
        for local_path in _AGENT_FILES:
            sftp.put(local_path, f"{tmp_dir}/{os.path.basename(local_path)}")
        sftp.close()

        _, stdout, _ = client.exec_command(
            f"cd {tmp_dir} && sudo bash install.sh 2>&1", timeout=240
        )
        exit_code = stdout.channel.recv_exit_status()
        output = stdout.read().decode("utf-8", errors="replace")

        client.exec_command(f"rm -rf {tmp_dir}")

        if exit_code != 0:
            client.close()
            return jsonify({"ok": False, "output": output, "error": f"El script terminó con código {exit_code}"}), 500

        client.close()

        # Dar tiempo al servicio wardnode-wf para arrancar completamente
        time.sleep(3)

        from app.encryption import encrypt_secret, EncryptionNotConfigured
        key_stored = True
        try:
            AppConfig.set("wf_ssh_private_key", encrypt_secret(ssh_key_text), encrypted=True)
            AppConfig.set("wf_ssh_port", ssh_port_raw)
        except EncryptionNotConfigured:
            key_stored = False

        log_audit("module.wf_install", resource_type="module", resource_name="wardnode-wf",
                  detail={"port": ssh_port_raw, "key_stored": key_stored})

        # Si hay dominio de consola configurado, programar el bloqueo del puerto 5000
        # con delay para que esta respuesta JSON llegue al cliente antes de que
        # iptables corte la conexión TCP:5000.
        console_url = None
        port_will_be_blocked = False
        if AppConfig.get("console_site_id") and os.path.exists(SOCKET_PATH):
            console_url = _get_console_url()
            if console_url:
                port_will_be_blocked = True
                _secure_port_async(delay=5)

        return jsonify({
            "ok": True,
            "output": output,
            "console_url": console_url,
            "port_will_be_blocked": port_will_be_blocked,
            "warning": None if key_stored else (
                "WARDNODE_SECRET_KEY no configurada — la clave SSH NO fue almacenada. "
                "Configura la variable y reinstala."
            ),
        })

    except paramiko.AuthenticationException:
        return jsonify({"ok": False, "error": "Autenticación SSH fallida — verifica usuario y clave privada"}), 401
    except (paramiko.SSHException, OSError) as e:
        return jsonify({"ok": False, "error": f"Error de conexión SSH: {e}"}), 500
    except FileNotFoundError as e:
        return jsonify({"ok": False, "error": f"Archivo del agente no encontrado en el contenedor: {e}"}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        try:
            client.close()
        except Exception:
            pass


@bp.post("/wf/generate-key")
@roles_required(ROLE_ADMIN)
def wf_generate_key():
    """Genera par RSA-4096, instala la pública en el host vía password SSH
    y almacena la privada cifrada en AppConfig. No retorna la clave al frontend."""
    try:
        import paramiko
    except ImportError:
        return jsonify({"ok": False, "error": "Dependencia 'paramiko' no instalada en el contenedor."}), 500

    ssh_port_raw = request.form.get("ssh_port", "22").strip() or "22"
    ssh_password = request.form.get("ssh_password", "").strip()

    if not ssh_password:
        return jsonify({"ok": False, "error": "Contraseña root requerida"}), 400
    try:
        ssh_port = int(ssh_port_raw)
        if not (1 <= ssh_port <= 65535):
            raise ValueError
    except ValueError:
        return jsonify({"ok": False, "error": "Puerto SSH inválido"}), 400

    key = paramiko.RSAKey.generate(4096)

    key_io = io.StringIO()
    key.write_private_key(key_io)
    private_pem = key_io.getvalue()

    pub_key = f"{key.get_name()} {key.get_base64()} wardnode-generated"

    client, stored_b64, tofu_policy = _make_ssh_client(_SSH_HOST, ssh_port)
    try:
        client.connect(
            _SSH_HOST, port=ssh_port, username="root",
            password=ssh_password, timeout=15,
            look_for_keys=False, allow_agent=False,
        )
        _tofu_persist(stored_b64, tofu_policy)

        # Crear /root/.ssh con permisos (sin datos de usuario interpolados en el comando)
        _, out, _ = client.exec_command("mkdir -p /root/.ssh && chmod 700 /root/.ssh", timeout=10)
        out.channel.recv_exit_status()

        # Escribir authorized_keys vía SFTP — elimina el riesgo de shell injection
        sftp = client.open_sftp()
        try:
            try:
                with sftp.open("/root/.ssh/authorized_keys", "r") as f:
                    existing = f.read().decode("utf-8", errors="replace")
            except OSError:
                existing = ""

            if pub_key not in existing:
                new_content = (existing.rstrip("\n") + "\n" + pub_key + "\n") if existing else (pub_key + "\n")
                with sftp.open("/root/.ssh/authorized_keys", "w") as f:
                    f.write(new_content.encode())
        finally:
            sftp.close()

        _, out, _ = client.exec_command("chmod 600 /root/.ssh/authorized_keys", timeout=10)
        out.channel.recv_exit_status()

        from app.encryption import encrypt_secret, EncryptionNotConfigured
        key_stored = True
        try:
            AppConfig.set("wf_ssh_private_key", encrypt_secret(private_pem), encrypted=True)
            AppConfig.set("wf_ssh_port", ssh_port_raw)
        except EncryptionNotConfigured:
            key_stored = False

        return jsonify({
            "ok": True,
            "warning": None if key_stored else (
                "WARDNODE_SECRET_KEY no configurada — la clave SSH NO fue almacenada. "
                "Configura la variable y reinstala para habilitar auto-reutilización en CS."
            ),
        })

    except paramiko.AuthenticationException:
        return jsonify({"ok": False, "error": "Contraseña root incorrecta"}), 401
    except (paramiko.SSHException, OSError) as e:
        return jsonify({"ok": False, "error": f"Error de conexión SSH: {e}"}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        try:
            client.close()
        except Exception:
            pass


@bp.post("/wf/status")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
def wf_status():
    if AppConfig.get("module_wf_enabled") != "1":
        return jsonify({"ok": False, "error": "Módulo WF no habilitado"}), 403
    result = send_command("status")
    if result.get("ok"):
        defaults = send_command("check_defaults")
        verbose_out = defaults.get("output", "")
        result["initialized"] = "deny (incoming)" in verbose_out.lower()
        result["defaults_output"] = verbose_out
    return jsonify(result)



@bp.post("/wf/init")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
def wf_init():
    if AppConfig.get("module_wf_enabled") != "1":
        return jsonify({"ok": False, "error": "Módulo WF no habilitado"}), 403
    ssh_port = request.form.get("ssh_port", "22").strip() or "22"
    if not valid_port(ssh_port):
        return jsonify({"ok": False, "error": "Puerto SSH inválido"}), 400
    return jsonify(send_command("init_firewall", ssh_port=ssh_port))


@bp.post("/wf/allow")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
def wf_allow():
    if AppConfig.get("module_wf_enabled") != "1":
        return jsonify({"ok": False, "error": "Módulo WF no habilitado"}), 403

    target_type = request.form.get("type", "port")

    if target_type == "ip":
        ip = request.form.get("ip", "").strip()
        if not valid_ip(ip):
            return jsonify({"ok": False, "error": "IP o CIDR inválido"}), 400
        return jsonify(send_command("allow_ip", ip=ip))
    else:
        port = request.form.get("port", "").strip()
        proto = request.form.get("proto", "tcp").strip()
        if not valid_port(port):
            return jsonify({"ok": False, "error": "Puerto inválido (1–65535)"}), 400
        if not valid_proto(proto):
            return jsonify({"ok": False, "error": "Protocolo inválido"}), 400
        return jsonify(send_command("allow_port", port=port, proto=proto))


@bp.post("/wf/deny")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
def wf_deny():
    if AppConfig.get("module_wf_enabled") != "1":
        return jsonify({"ok": False, "error": "Módulo WF no habilitado"}), 403

    target_type = request.form.get("type", "port")

    if target_type == "ip":
        ip = request.form.get("ip", "").strip()
        if not valid_ip(ip):
            return jsonify({"ok": False, "error": "IP o CIDR inválido"}), 400
        return jsonify(send_command("deny_ip", ip=ip))
    else:
        port = request.form.get("port", "").strip()
        proto = request.form.get("proto", "tcp").strip()
        if not valid_port(port):
            return jsonify({"ok": False, "error": "Puerto inválido (1–65535)"}), 400
        if not valid_proto(proto):
            return jsonify({"ok": False, "error": "Protocolo inválido"}), 400
        return jsonify(send_command("deny_port", port=port, proto=proto))


@bp.post("/wf/delete")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
def wf_delete():
    if AppConfig.get("module_wf_enabled") != "1":
        return jsonify({"ok": False, "error": "Módulo WF no habilitado"}), 403
    rule_num = request.form.get("rule_num", "").strip()
    if not valid_rule_num(rule_num):
        return jsonify({"ok": False, "error": "Número de regla inválido"}), 400
    return jsonify(send_command("delete_rule", rule_num=rule_num))


@bp.post("/wf/ipv6-status")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
def wf_ipv6_status():
    if AppConfig.get("module_wf_enabled") != "1":
        return jsonify({"ok": False, "error": "Módulo WF no habilitado"}), 403
    return jsonify(send_command("get_ipv6_status"))


@bp.post("/wf/set-ipv6")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
def wf_set_ipv6():
    if AppConfig.get("module_wf_enabled") != "1":
        return jsonify({"ok": False, "error": "Módulo WF no habilitado"}), 403
    enabled_str = request.form.get("enabled", "").strip()
    if enabled_str not in ("true", "false"):
        return jsonify({"ok": False, "error": "Valor inválido"}), 400
    return jsonify(send_command("set_ipv6", enabled=(enabled_str == "true")))


@bp.post("/wf/docker-ports")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("30 per minute")
def wf_docker_ports():
    r = _wf_required()
    if r:
        return jsonify({"ok": False, "error": "Módulo WF no habilitado"}), 403
    return jsonify(send_command("list_docker_ports", timeout=20))


@bp.post("/wf/protect-port")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("20 per minute")
def wf_protect_port():
    r = _wf_required()
    if r:
        return jsonify({"ok": False, "error": "Módulo WF no habilitado"}), 403
    port = request.form.get("port", "").strip()
    if not valid_port(port):
        return jsonify({"ok": False, "error": "Puerto inválido (1–65535)"}), 400
    result = send_command("protect_host_port", port=port, timeout=15)
    if result.get("ok"):
        log_audit("wf.protect_port", resource_type="port", resource_name=port,
                  detail={"source": "wf_panel"})
    return jsonify(result)


@bp.post("/wf/unprotect-port")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("20 per minute")
def wf_unprotect_port():
    r = _wf_required()
    if r:
        return jsonify({"ok": False, "error": "Módulo WF no habilitado"}), 403
    port = request.form.get("port", "").strip()
    if not valid_port(port):
        return jsonify({"ok": False, "error": "Puerto inválido (1–65535)"}), 400
    result = send_command("unprotect_host_port", port=port, timeout=15)
    if result.get("ok"):
        log_audit("wf.unprotect_port", resource_type="port", resource_name=port,
                  detail={"source": "wf_panel"})
    return jsonify(result)


@bp.post("/wf/limit-ssh")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("10 per minute")
def wf_limit_ssh():
    r = _wf_required()
    if r:
        return jsonify({"ok": False, "error": "Módulo WF no habilitado"}), 403
    port = request.form.get("port", "22").strip()
    if not valid_port(port):
        return jsonify({"ok": False, "error": "Puerto inválido"}), 400
    result = send_command("limit_port", port=port, timeout=15)
    if result.get("ok"):
        log_audit("wf.limit_ssh", resource_type="port", resource_name=port)
    return jsonify(result)


@bp.post("/wf/unlimit-ssh")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("10 per minute")
def wf_unlimit_ssh():
    r = _wf_required()
    if r:
        return jsonify({"ok": False, "error": "Módulo WF no habilitado"}), 403
    port = request.form.get("port", "22").strip()
    if not valid_port(port):
        return jsonify({"ok": False, "error": "Puerto inválido"}), 400
    result = send_command("unlimit_port", port=port, timeout=15)
    if result.get("ok"):
        log_audit("wf.unlimit_ssh", resource_type="port", resource_name=port)
    return jsonify(result)


# ── WardNode OBS ──────────────────────────────────────────────────────

def _obs_required():
    if AppConfig.get("module_obs_enabled") != "1":
        return redirect(url_for("modules.index"))
    return None


_OBS_NGINX_CONF = (
    "# WardNode OBS — Grafana reverse proxy (auto-generated)\n"
    "server {\n"
    "    listen 80;\n"
    "    server_name _;\n"
    "\n"
    "    location /obs/ {\n"
    "        modsecurity off;\n"
    "        auth_request /_wardnode_obs_auth;\n"
    "        auth_request_set $wn_user $upstream_http_x_webauth_user;\n"
    "        auth_request_set $wn_role $upstream_http_x_webauth_role;\n"
    "        proxy_pass         http://127.0.0.1:3000$request_uri;\n"
    "        proxy_set_header   Host              $host;\n"
    "        proxy_set_header   X-Real-IP         $remote_addr;\n"
    "        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;\n"
    "        proxy_set_header   X-Forwarded-Proto $scheme;\n"
    "        proxy_set_header   X-WEBAUTH-USER    $wn_user;\n"
    "        proxy_set_header   X-WEBAUTH-ROLE    $wn_role;\n"
    "        proxy_http_version 1.1;\n"
    "        proxy_set_header   Upgrade           $http_upgrade;\n"
    "        proxy_set_header   Connection        \"upgrade\";\n"
    "        proxy_hide_header X-Frame-Options;\n"
    "        proxy_hide_header Content-Security-Policy;\n"
    "        add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
    "        add_header Content-Security-Policy \"frame-ancestors 'self'\" always;\n"
    "        proxy_read_timeout 300s;\n"
    "    }\n"
    "\n"
    "    location = /_wardnode_obs_auth {\n"
    "        internal;\n"
    "        proxy_pass http://127.0.0.1:5000/modules/obs/auth;\n"
    "        proxy_pass_request_body off;\n"
    "        proxy_set_header Content-Length \"\";\n"
    "        proxy_set_header X-Original-URI $request_uri;\n"
    "        proxy_set_header X-Forwarded-Proto $scheme;\n"
    "        proxy_set_header Host $host;\n"
    "    }\n"
    "}\n"
)


def _inject_obs_nginx_conf(docker_client) -> bool:
    """Inyecta obs.conf en el proxy si no existe y hace reload.
    Retorna True si obs.conf ya estaba o fue inyectado con éxito."""
    import tarfile

    try:
        proxy = docker_client.containers.get("wardnode-proxy")
        # Verificar si el contenido actual coincide con el esperado
        exit_code, current = proxy.exec_run("cat /etc/nginx/conf.d/obs.conf")
        if exit_code == 0 and current.decode("utf-8", errors="replace") == _OBS_NGINX_CONF:
            return True  # Ya existe y está actualizado

        buf = io.BytesIO()
        conf_bytes = _OBS_NGINX_CONF.encode()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="obs.conf")
            info.size = len(conf_bytes)
            tar.addfile(info, io.BytesIO(conf_bytes))
        buf.seek(0)
        proxy.put_archive("/etc/nginx/conf.d/", buf)
        proxy.exec_run("nginx -s reload")
        return True
    except Exception:
        return False


@bp.post("/obs/activate")
@roles_required(ROLE_ADMIN)
def obs_activate():
    import os
    import subprocess
    import time

    try:
        import docker as docker_sdk
    except ImportError:
        return jsonify({"ok": False, "step": "docker", "error": "SDK de Docker no instalado en el contenedor"}), 500

    _OBS_CONTAINERS = ["wardnode-loki", "wardnode-grafana", "wardnode-alloy", "wardnode-prometheus", "wardnode-nginx-exporter"]

    try:
        client = docker_sdk.from_env()
    except Exception as e:
        return jsonify({"ok": False, "step": "docker", "error": f"Docker no disponible: {e}"}), 500

    # ── Fase 1: intentar iniciar contenedores existentes via SDK ──────────
    not_found = []
    for name in _OBS_CONTAINERS:
        try:
            c = client.containers.get(name)
            if c.status != "running":
                c.start()
        except docker_sdk.errors.NotFound:
            not_found.append(name)
        except Exception as e:
            return jsonify({"ok": False, "step": "containers", "error": f"Error al iniciar {name}: {e}"}), 500

    # ── Fase 2: si faltan contenedores, crearlos con docker compose ───────
    if not_found:
        project_dir = os.environ.get("WARDNODE_PROJECT_DIR", "").strip()
        if not project_dir:
            return jsonify({
                "ok": False,
                "step": "compose",
                "error": (
                    "Los contenedores OBS no existen todavía y la variable "
                    "WARDNODE_PROJECT_DIR no está configurada en el servidor. "
                    "Añádela al archivo .env apuntando al directorio del proyecto "
                    "(ej: WARDNODE_PROJECT_DIR=/opt/wardnode) y reinicia el contenedor consola."
                ),
            }), 500

        compose_file = os.path.join(project_dir, "docker-compose.vps.yml")
        if not os.path.isfile(compose_file):
            return jsonify({
                "ok": False,
                "step": "compose",
                "error": (
                    f"No se encontró docker-compose.vps.yml en '{project_dir}'. "
                    "Verifica que WARDNODE_PROJECT_DIR apunta al directorio correcto del proyecto."
                ),
            }), 500

        try:
            result = subprocess.run(
                [
                    "docker", "compose", "-f", compose_file, "--profile", "obs",
                    "up", "-d", "--no-build", "--no-deps", "--no-recreate",
                    "loki", "grafana", "alloy", "prometheus", "nginx-exporter",
                ],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=project_dir,
            )
        except FileNotFoundError:
            return jsonify({
                "ok": False,
                "step": "compose",
                "error": "Comando 'docker compose' no encontrado. Reconstruye la imagen del contenedor consola.",
            }), 500
        except subprocess.TimeoutExpired:
            return jsonify({
                "ok": False,
                "step": "compose",
                "error": "Timeout al ejecutar docker compose (>120 s). Revisa el estado manualmente con: docker compose --profile obs ps",
            }), 500

        if result.returncode != 0:
            err_output = (result.stderr or result.stdout or "").strip()
            return jsonify({
                "ok": False,
                "step": "compose",
                "error": f"docker compose falló (código {result.returncode}): {err_output[:500]}",
            }), 500

    # ── Fase 3: verificar que los contenedores estén corriendo (máx 30 s) ──
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            all_running = all(
                client.containers.get(name).status == "running"
                for name in _OBS_CONTAINERS
            )
            if all_running:
                break
        except Exception:
            pass
        time.sleep(3)
    else:
        not_running = []
        for name in _OBS_CONTAINERS:
            try:
                c = client.containers.get(name)
                if c.status != "running":
                    not_running.append(f"{name} ({c.status})")
            except Exception:
                not_running.append(f"{name} (no encontrado)")
        return jsonify({
            "ok": False,
            "step": "health",
            "error": f"Contenedores no arrancaron: {', '.join(not_running)}. "
                     "Revisa logs con: docker logs <nombre>",
        }), 500

    # ── Fase 3b: esperar a que Grafana responda HTTP (no fatal, máx 30 s) ──
    http_deadline = time.time() + 30
    while time.time() < http_deadline:
        if _grafana_http_ready():
            break
        time.sleep(2)
    # Si Grafana aún no responde el frontend continuará su propio polling.

    # ── Fase 4: habilitar OBS en configs de sites y recargar Nginx ─────
    AppConfig.set("module_obs_enabled", "1")

    try:
        from app.proxy.geoip_blocklist import reload_nginx
        from app.proxy.services import render_nginx_configs

        render_nginx_configs()
        ok_reload, err_reload = reload_nginx()
        if not ok_reload:
            return jsonify({
                "ok": False,
                "step": "nginx",
                "error": f"OBS activo, pero Nginx no pudo recargar: {err_reload}",
            }), 500
    except Exception as e:
        return jsonify({
            "ok": False,
            "step": "nginx",
            "error": f"OBS activo, pero no se pudieron regenerar configs Nginx: {e}",
        }), 500

    # Mantener obs.conf como fallback para instalaciones sin site configurado.
    _inject_obs_nginx_conf(client)
    return jsonify({"ok": True})


@bp.get("/obs/")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def obs_index():
    if (r := _obs_required()):
        return r
    return render_template("modules/obs.html")


@bp.get("/obs/fullscreen")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def obs_fullscreen():
    if (r := _obs_required()):
        return r
    return render_template("modules/obs_fullscreen.html")


@bp.get("/obs/auth")
@limiter.exempt
def obs_auth():
    if AppConfig.get("module_obs_enabled") != "1":
        return "", 403
    if not current_user.is_authenticated:
        return "", 401
    if not current_user.has_role(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER):
        return "", 403
    grafana_role = "Editor" if current_user.has_role(ROLE_ADMIN) else "Viewer"
    resp = make_response("", 204)
    resp.headers["X-WEBAUTH-USER"] = f"wn-{current_user.id}"
    resp.headers["X-WEBAUTH-ROLE"] = grafana_role
    return resp


@bp.post("/obs/status")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def obs_status():
    if AppConfig.get("module_obs_enabled") != "1":
        return jsonify({"ok": False, "loki": False, "grafana": False, "alloy": False,
                        "prometheus": False, "error": "Módulo OBS no habilitado"}), 403
    try:
        import docker as docker_sdk
        client = docker_sdk.from_env()
    except Exception:
        return jsonify({"ok": False, "loki": False, "grafana": False, "alloy": False,
                        "prometheus": False, "error": "Docker no disponible"}), 500

    def _is_running(name):
        try:
            return client.containers.get(name).status == "running"
        except Exception:
            return False

    loki_ok = _is_running("wardnode-loki")
    grafana_ok = _is_running("wardnode-grafana")
    alloy_ok = _is_running("wardnode-alloy")
    prometheus_ok = _is_running("wardnode-prometheus")
    nginx_exporter_ok = _is_running("wardnode-nginx-exporter")

    # Re-inyectar obs.conf si el proxy fue reiniciado y lo perdió
    if grafana_ok:
        try:
            from app.proxy.geoip_blocklist import reload_nginx
            from app.proxy.services import render_nginx_configs

            render_nginx_configs()
            reload_nginx()
        except Exception:
            pass
        _inject_obs_nginx_conf(client)

    return jsonify({
        "ok": loki_ok and grafana_ok and alloy_ok and prometheus_ok and nginx_exporter_ok,
        "loki": loki_ok,
        "grafana": grafana_ok,
        "alloy": alloy_ok,
        "prometheus": prometheus_ok,
        "nginx_exporter": nginx_exporter_ok,
    })


def _grafana_http_ready(timeout: float = 2.0) -> bool:
    """Probe HTTP real a Grafana /api/health. True solo si el servidor responde 200."""
    import urllib.request
    try:
        req = urllib.request.Request(f"{_GRAFANA_URL}/api/health", method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


@bp.post("/obs/grafana-ready")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER)
def obs_grafana_ready():
    """Probe ligero de readiness HTTP de Grafana — sin Docker ni reloads de Nginx.
    Diseñado para polling frecuente desde el frontend (cada ~3 s)."""
    if AppConfig.get("module_obs_enabled") != "1":
        return jsonify({"ready": False, "error": "Módulo OBS no habilitado"}), 403
    return jsonify({"ready": _grafana_http_ready()})


# ── WardNode SYS — Contenedores ───────────────────────────────────────

def _sys_container_states() -> dict:
    """Retorna estado de cada servicio gestionable. Una sola llamada Docker SDK."""
    running = set()
    try:
        import docker as docker_sdk
        client = docker_sdk.from_env()
        running = {c.name for c in client.containers.list()}
    except Exception:
        pass
    return {
        "proxy":          "wardnode-proxy"          in running,
        "loki":           "wardnode-loki"           in running,
        "grafana":        "wardnode-grafana"        in running,
        "alloy":          "wardnode-alloy"          in running,
        "prometheus":     "wardnode-prometheus"     in running,
        "nginx-exporter": "wardnode-nginx-exporter" in running,
        "fluent-bit":     "wardnode-fluent-bit"     in running,
    }


@bp.get("/sys/")
@roles_required(ROLE_ADMIN)
def sys_index():
    wf_active = AppConfig.get("module_wf_enabled") == "1"
    return render_template("modules/sys.html", states=_sys_container_states(), wf_active=wf_active)


@bp.get("/sys/status")
@roles_required(ROLE_ADMIN)
def sys_status():
    return jsonify(_sys_container_states())


@bp.post("/sys/restart/<target>")
@roles_required(ROLE_ADMIN)
def sys_restart(target: str):
    _DOCKER_TARGETS = {
        "proxy", "loki", "grafana", "alloy", "prometheus", "fluent-bit",
        "nginx-exporter", "crowdsec", "crowdsec-bouncer",
    }

    if target in _DOCKER_TARGETS:
        container_name = f"wardnode-{target}"
        try:
            import docker as docker_sdk
            client = docker_sdk.from_env()
            container = client.containers.get(container_name)
            container.restart(timeout=30)
            log_audit("system.container_restart", resource_type="system",
                      resource_name=container_name)
            return jsonify({"ok": True})
        except Exception as e:
            log_audit("system.container_restart", resource_type="system",
                      resource_name=container_name, severity="error", status="failure",
                      detail={"error": str(e)})
            return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": False, "error": "Target desconocido"}), 400


# ── WardNode DDoS / CrowdSec ──────────────────────────────────────────

import re as _re
import secrets as _secrets

_DDOS_CONTAINERS  = ["wardnode-crowdsec", "wardnode-crowdsec-bouncer"]
_DDOS_DURATION_RE = _re.compile(r"^\d+[smhd]$")
_DDOS_REASON_RE   = _re.compile(r"^[\w\-]{1,64}$")
_DDOS_IP_RE       = _re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]{2,39}$"
)


def _ddos_required():
    if AppConfig.get("module_ddos_enabled") != "1":
        return redirect(url_for("modules.index"))
    return None


def _ddos_client():
    """Devuelve (client, None) o (None, error_json) del SDK de Docker."""
    try:
        import docker as docker_sdk
        return docker_sdk.from_env(), None
    except ImportError:
        return None, jsonify({"ok": False, "error": "SDK de Docker no instalado"}), 500
    except Exception as e:
        return None, jsonify({"ok": False, "step": "docker", "error": f"Docker no disponible: {e}"}), 500


@bp.get("/ddos/")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
def ddos_index():
    if (r := _ddos_required()):
        return r
    safe_ips = AppConfig.get("ddos_safe_ips") or ""
    return render_template("modules/ddos.html", ddos_safe_ips=safe_ips)


@bp.get("/ddos/status")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
def ddos_status():
    if AppConfig.get("module_ddos_enabled") != "1":
        return jsonify({"ok": False, "error": "Módulo DDoS no habilitado"}), 403
    running = set()
    try:
        import docker as docker_sdk
        client = docker_sdk.from_env()
        running = {c.name for c in client.containers.list()}
    except Exception:
        pass
    return jsonify({
        "ok":      all(n in running for n in _DDOS_CONTAINERS),
        "crowdsec": "wardnode-crowdsec"         in running,
        "bouncer":  "wardnode-crowdsec-bouncer" in running,
    })


@bp.post("/ddos/activate")
@roles_required(ROLE_ADMIN)
def ddos_activate():
    """Activa el módulo DDoS: arranca CrowdSec + bouncer y registra la bouncer key."""
    import subprocess

    try:
        import docker as docker_sdk
    except ImportError:
        return jsonify({"ok": False, "step": "docker",
                        "error": "SDK de Docker no instalado en el contenedor"}), 500

    try:
        client = docker_sdk.from_env()
    except Exception as e:
        return jsonify({"ok": False, "step": "docker",
                        "error": f"Docker no disponible: {e}"}), 500

    # ── Obtener / generar la bouncer key (cifrada en AppConfig) ───────────
    from app.encryption import encrypt_secret, EncryptionNotConfigured
    bouncer_key = None
    try:
        bouncer_key = AppConfig.get_secret("ddos_bouncer_key")
    except Exception:
        pass
    if not bouncer_key:
        bouncer_key = _secrets.token_hex(32)
        try:
            AppConfig.set("ddos_bouncer_key", encrypt_secret(bouncer_key), encrypted=True)
        except EncryptionNotConfigured:
            return jsonify({
                "ok": False, "step": "secret",
                "error": (
                    "WARDNODE_SECRET_KEY no está configurada; no se puede persistir la "
                    "bouncer key de forma segura. Configúrala en el entorno del contenedor "
                    "consola y reinícialo antes de activar el módulo DDoS."
                ),
            }), 400

    # ── Fase 1: intentar iniciar contenedores existentes via SDK ──────────
    not_found = []
    for name in _DDOS_CONTAINERS:
        try:
            c = client.containers.get(name)
            if c.status != "running":
                c.start()
        except docker_sdk.errors.NotFound:
            not_found.append(name)
        except Exception as e:
            return jsonify({"ok": False, "step": "containers",
                            "error": f"Error al iniciar {name}: {e}"}), 500

    # ── Fase 2: si faltan contenedores, crearlos con docker compose ───────
    if not_found:
        project_dir = os.environ.get("WARDNODE_PROJECT_DIR", "").strip()
        if not project_dir:
            return jsonify({
                "ok": False, "step": "compose",
                "error": (
                    "Los contenedores CrowdSec no existen y WARDNODE_PROJECT_DIR no está "
                    "configurada. Añádela al .env apuntando al directorio del proyecto "
                    "(ej: WARDNODE_PROJECT_DIR=/opt/wardnode) y reinicia el contenedor consola."
                ),
            }), 500

        compose_file = os.path.join(project_dir, "docker-compose.vps.yml")
        if not os.path.isfile(compose_file):
            return jsonify({
                "ok": False, "step": "compose",
                "error": (
                    f"No se encontró docker-compose.vps.yml en '{project_dir}'. "
                    "Verifica que WARDNODE_PROJECT_DIR apunta al directorio correcto."
                ),
            }), 500

        # Preflight: verificar que el compose conoce los servicios ddos
        try:
            preflight = subprocess.run(
                ["docker", "compose", "-f", compose_file, "--profile", "ddos",
                 "config", "--services"],
                capture_output=True, text=True, timeout=30, cwd=project_dir,
                env={**os.environ, "WARDNODE_DDOS_BOUNCER_KEY": bouncer_key},
            )
            known = preflight.stdout.strip().splitlines()
            if "crowdsec" not in known or "crowdsec-bouncer" not in known:
                return jsonify({
                    "ok": False, "step": "compose",
                    "error": (
                        "El docker-compose.vps.yml en el host no define los servicios "
                        "'crowdsec'/'crowdsec-bouncer'. Actualiza el archivo a la versión "
                        f"que incluye el perfil 'ddos' en '{project_dir}' y reintenta."
                    ),
                }), 500
        except Exception:
            pass  # No fatal — el compose up fallará con mensaje claro si hay problema

        try:
            result = subprocess.run(
                [
                    "docker", "compose", "-f", compose_file, "--profile", "ddos",
                    "up", "-d", "--no-build", "--no-deps", "--no-recreate",
                    "crowdsec", "crowdsec-bouncer",
                ],
                capture_output=True, text=True, timeout=120, cwd=project_dir,
                env={**os.environ, "WARDNODE_DDOS_BOUNCER_KEY": bouncer_key},
            )
        except FileNotFoundError:
            return jsonify({"ok": False, "step": "compose",
                            "error": "Comando 'docker compose' no encontrado."}), 500
        except subprocess.TimeoutExpired:
            return jsonify({"ok": False, "step": "compose",
                            "error": "Timeout al ejecutar docker compose (>120 s)."}), 500

        if result.returncode != 0:
            err_output = (result.stderr or result.stdout or "").strip()
            return jsonify({"ok": False, "step": "compose",
                            "error": f"docker compose falló (código {result.returncode}): {err_output[:500]}"}), 500

    # ── Fase 3: health check contenedores (máx 30 s) ──────────────────────
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            all_running = all(
                client.containers.get(n).status == "running"
                for n in _DDOS_CONTAINERS
            )
            if all_running:
                break
        except Exception:
            pass
        time.sleep(3)
    else:
        not_running = []
        for n in _DDOS_CONTAINERS:
            try:
                c = client.containers.get(n)
                if c.status != "running":
                    not_running.append(f"{n} ({c.status})")
            except Exception:
                not_running.append(f"{n} (no encontrado)")
        return jsonify({
            "ok": False, "step": "health",
            "error": f"Contenedores no arrancaron: {', '.join(not_running)}. "
                     "Revisa logs con: docker logs <nombre>",
        }), 500

    # ── Fase 4: registrar bouncer key en el daemon CrowdSec ───────────────
    try:
        crowdsec_c = client.containers.get("wardnode-crowdsec")
        crowdsec_c.exec_run(
            ["cscli", "bouncers", "add", "wardnode-bouncer",
             "--key", bouncer_key, "--overwrite"],
            user="root",
        )
    except Exception as e:
        return jsonify({"ok": False, "step": "bouncer_key",
                        "error": f"No se pudo registrar la bouncer key: {e}"}), 500

    # ── Fase 5: esperar a que el bouncer también corra ────────────────────
    deadline2 = time.time() + 20
    while time.time() < deadline2:
        try:
            if client.containers.get("wardnode-crowdsec-bouncer").status == "running":
                break
        except Exception:
            pass
        time.sleep(2)

    AppConfig.set("module_ddos_enabled", "1")
    log_audit("ddos.activate", resource_type="module", resource_name="ddos")

    # Arrancar thread de ingesta si no estaba corriendo
    try:
        from flask import current_app
        from app.ddos.ingest import start_ddos_ingest_thread
        start_ddos_ingest_thread(current_app._get_current_object())
    except Exception:
        pass

    return jsonify({"ok": True})


@bp.post("/ddos/deactivate")
@roles_required(ROLE_ADMIN)
def ddos_deactivate():
    try:
        import docker as docker_sdk
        client = docker_sdk.from_env()
        for name in reversed(_DDOS_CONTAINERS):
            try:
                client.containers.get(name).stop(timeout=15)
            except Exception as e:
                log_audit("ddos.deactivate", resource_type="module", resource_name="ddos",
                          severity="warning", detail={"error": str(e)})
    except Exception:
        pass
    AppConfig.set("module_ddos_enabled", "0")
    log_audit("ddos.deactivate", resource_type="module", resource_name="ddos")
    return jsonify({"ok": True})


@bp.post("/ddos/decisions")
@roles_required(ROLE_ADMIN, ROLE_OPERATOR)
@limiter.limit("30 per minute")
def ddos_decisions():
    if AppConfig.get("module_ddos_enabled") != "1":
        return jsonify({"ok": False, "error": "Módulo no habilitado"}), 403
    try:
        import docker as docker_sdk
        client = docker_sdk.from_env()
        crowdsec_c = client.containers.get("wardnode-crowdsec")
        exit_code, output = crowdsec_c.exec_run(
            ["cscli", "decisions", "list", "-o", "json"], user="root"
        )
        raw = output.decode("utf-8", errors="replace").strip()
        if exit_code != 0:
            return jsonify({"ok": False, "error": f"cscli terminó con código {exit_code}: {raw[:300]}"}), 500
        import json as _json
        decisions = _json.loads(raw) if raw else []
        return jsonify({"ok": True, "decisions": decisions or []})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.post("/ddos/ban")
@roles_required(ROLE_ADMIN)
@limiter.limit("10 per minute")
def ddos_ban():
    if AppConfig.get("module_ddos_enabled") != "1":
        return jsonify({"ok": False, "error": "Módulo no habilitado"}), 403

    ip       = request.form.get("ip", "").strip()
    duration = request.form.get("duration", "24h").strip()
    reason   = request.form.get("reason", "manual-ban").strip()

    if not ip:
        return jsonify({"ok": False, "error": "IP requerida"}), 400
    if not _DDOS_DURATION_RE.match(duration):
        return jsonify({"ok": False, "error": "Duración inválida (ej: 1h, 24h, 7d)"}), 400
    if not _DDOS_REASON_RE.match(reason):
        return jsonify({"ok": False, "error": "Razón inválida (solo letras, números y guiones, máx 64 caracteres)"}), 400

    # Obtener IP del cliente (respeta X-Forwarded-For si hay proxy)
    request_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()

    from app.ddos.safety import is_ban_safe
    safe, motivo = is_ban_safe(ip, request_ip)
    if not safe:
        return jsonify({"ok": False, "error": motivo}), 400

    try:
        import docker as docker_sdk
        client = docker_sdk.from_env()
        crowdsec_c = client.containers.get("wardnode-crowdsec")
        exit_code, output = crowdsec_c.exec_run(
            ["cscli", "decisions", "add", "--ip", ip,
             "--duration", duration, "--reason", reason, "--type", "ban"],
            user="root",
        )
        raw = output.decode("utf-8", errors="replace").strip()
        if exit_code != 0:
            return jsonify({"ok": False, "error": f"cscli error: {raw[:300]}"}), 500
        log_audit("ddos.ban", resource_type="ip", resource_name=ip,
                  detail={"duration": duration, "reason": reason})
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.post("/ddos/unban")
@roles_required(ROLE_ADMIN)
@limiter.limit("10 per minute")
def ddos_unban():
    if AppConfig.get("module_ddos_enabled") != "1":
        return jsonify({"ok": False, "error": "Módulo no habilitado"}), 403

    ip = request.form.get("ip", "").strip()
    if not ip or not _DDOS_IP_RE.match(ip):
        return jsonify({"ok": False, "error": "IP inválida"}), 400

    try:
        import docker as docker_sdk
        client = docker_sdk.from_env()
        crowdsec_c = client.containers.get("wardnode-crowdsec")
        exit_code, output = crowdsec_c.exec_run(
            ["cscli", "decisions", "delete", "--ip", ip],
            user="root",
        )
        raw = output.decode("utf-8", errors="replace").strip()
        if exit_code != 0:
            return jsonify({"ok": False, "error": f"cscli error: {raw[:300]}"}), 500
        log_audit("ddos.unban", resource_type="ip", resource_name=ip)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.post("/ddos/safe-ips")
@roles_required(ROLE_ADMIN)
def ddos_safe_ips_update():
    """Actualiza la allowlist de IPs protegidas (ddos_safe_ips en AppConfig)."""
    if AppConfig.get("module_ddos_enabled") != "1":
        return jsonify({"ok": False, "error": "Módulo no habilitado"}), 403
    raw = request.form.get("safe_ips", "").strip()
    # Validar cada IP antes de guardar
    import ipaddress
    ips = []
    for candidate in raw.split(","):
        candidate = candidate.strip()
        if not candidate:
            continue
        try:
            # Normalizar a forma canónica antes de guardar (evita bypass por forma equivalente)
            ips.append(str(ipaddress.ip_address(candidate)))
        except ValueError:
            return jsonify({"ok": False, "error": f"IP inválida en la lista: {candidate}"}), 400
    AppConfig.set("ddos_safe_ips", ",".join(ips))
    log_audit("ddos.safe_ips_update", resource_type="config", resource_name="ddos_safe_ips",
              detail={"count": len(ips)})
    return jsonify({"ok": True, "count": len(ips)})
