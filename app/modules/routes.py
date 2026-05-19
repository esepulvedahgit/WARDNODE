import io
import os
import re
import time

from flask import jsonify, redirect, render_template, request, url_for
from flask_login import current_user

from app.auth.decorators import roles_required
from app.extensions import db
from app.models import AppConfig, ROLE_ADMIN
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
        "id": "cs",
        "name": "WardNode CS",
        "description": "Protección IDS/IPS con CrowdSec. Detecta ataques SSH y bloquea IPs "
                       "automáticamente en el firewall del host. Requiere WardNode WF activo.",
        "icon": "bi-shield-shaded",
        "config_key": "module_cs_enabled",
        "endpoint": "modules.cs_index",
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
]


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

    if name == "cs" and not current:
        if AppConfig.get("module_wf_enabled") != "1":
            flash("WardNode WF debe estar activo para activar WardNode CS.", "danger")
            return redirect(url_for("modules.index"))

    if name == "obs" and not current:
        flash("Usa el botón 'Activar' para iniciar el proceso de verificación de OBS.", "info")
        return redirect(url_for("modules.index"))

    if name == "cs":
        action = "cs_stop_services" if current else "cs_start_services"
        result = send_command(action)
        if not result.get("ok"):
            err = result.get("error", "error desconocido")
            if current:
                flash(
                    f"Módulo desactivado, pero no se pudieron detener los servicios en el host: {err}. "
                    "Puedes detenerlos manualmente: sudo systemctl stop crowdsec crowdsec-firewall-bouncer",
                    "warning",
                )
            # Si falla al iniciar (e.g. CS no instalado aún) no mostramos nada —
            # el panel CS mostrará el formulario de instalación normalmente.

    AppConfig.set(module["config_key"], "0" if current else "1")
    return redirect(url_for("modules.index"))


# ── WardNode WF ───────────────────────────────────────────────────────

def _wf_required():
    """Returns None if access is allowed, otherwise a redirect response."""
    if AppConfig.get("module_wf_enabled") != "1":
        return redirect(url_for("modules.index"))
    return None


@bp.get("/wf/")
@roles_required(ROLE_ADMIN)
def wf_index():
    if (r := _wf_required()):
        return r
    ssh_hardened = AppConfig.get("wf_ssh_hardened") == "1"
    return render_template("modules/wf.html", socket_path=SOCKET_PATH, ssh_hardened=ssh_hardened)


_SSH_USER_RE = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")
_SSH_HOST = "host.docker.internal"
_AGENT_FILES = [
    "/app/host-agent/wardnode-wf-agent.py",
    "/app/host-agent/wardnode-wf.service",
    "/app/host-agent/wardnode-set-ipv6.sh",
    "/app/host-agent/wardnode-cs-control.sh",
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

        from app.encryption import encrypt_secret, EncryptionNotConfigured
        key_stored = True
        try:
            AppConfig.set("wf_ssh_private_key", encrypt_secret(ssh_key_text), encrypted=True)
            AppConfig.set("wf_ssh_port", ssh_port_raw)
        except EncryptionNotConfigured:
            key_stored = False

        # Limpiar flag de hardening si es una reinstalación (el host puede haber cambiado)
        AppConfig.set("wf_ssh_hardened", "0")

        return jsonify({
            "ok": True,
            "output": output,
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
@roles_required(ROLE_ADMIN)
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
@roles_required(ROLE_ADMIN)
def wf_init():
    if AppConfig.get("module_wf_enabled") != "1":
        return jsonify({"ok": False, "error": "Módulo WF no habilitado"}), 403
    ssh_port = request.form.get("ssh_port", "22").strip() or "22"
    if not valid_port(ssh_port):
        return jsonify({"ok": False, "error": "Puerto SSH inválido"}), 400
    return jsonify(send_command("init_firewall", ssh_port=ssh_port))


@bp.post("/wf/allow")
@roles_required(ROLE_ADMIN)
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
@roles_required(ROLE_ADMIN)
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
@roles_required(ROLE_ADMIN)
def wf_delete():
    if AppConfig.get("module_wf_enabled") != "1":
        return jsonify({"ok": False, "error": "Módulo WF no habilitado"}), 403
    rule_num = request.form.get("rule_num", "").strip()
    if not valid_rule_num(rule_num):
        return jsonify({"ok": False, "error": "Número de regla inválido"}), 400
    return jsonify(send_command("delete_rule", rule_num=rule_num))


@bp.post("/wf/ipv6-status")
@roles_required(ROLE_ADMIN)
def wf_ipv6_status():
    if AppConfig.get("module_wf_enabled") != "1":
        return jsonify({"ok": False, "error": "Módulo WF no habilitado"}), 403
    return jsonify(send_command("get_ipv6_status"))


@bp.post("/wf/set-ipv6")
@roles_required(ROLE_ADMIN)
def wf_set_ipv6():
    if AppConfig.get("module_wf_enabled") != "1":
        return jsonify({"ok": False, "error": "Módulo WF no habilitado"}), 403
    enabled_str = request.form.get("enabled", "").strip()
    if enabled_str not in ("true", "false"):
        return jsonify({"ok": False, "error": "Valor inválido"}), 400
    return jsonify(send_command("set_ipv6", enabled=(enabled_str == "true")))


@bp.post("/wf/harden-ssh")
@roles_required(ROLE_ADMIN)
def wf_harden_ssh():
    """Aplica PermitRootLogin prohibit-password en sshd_config del host (login root solo por llave)."""
    if AppConfig.get("module_wf_enabled") != "1":
        return jsonify({"ok": False, "error": "Módulo WF no habilitado"}), 403

    try:
        import paramiko
    except ImportError:
        return jsonify({"ok": False, "error": "Dependencia 'paramiko' no instalada en el contenedor."}), 500

    ssh_port_raw = AppConfig.get("wf_ssh_port") or "22"
    try:
        ssh_port = int(ssh_port_raw)
        if not (1 <= ssh_port <= 65535):
            raise ValueError
    except ValueError:
        return jsonify({"ok": False, "error": "Puerto SSH inválido en configuración"}), 400

    try:
        ssh_key_text = AppConfig.get_secret("wf_ssh_private_key") or ""
    except Exception:
        ssh_key_text = ""
    if not ssh_key_text:
        return jsonify({"ok": False, "error": "Clave SSH no disponible — genera una desde el módulo WF"}), 400

    key = None
    for key_cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
        try:
            key = key_cls.from_private_key(io.StringIO(ssh_key_text))
            break
        except Exception:
            continue
    if key is None:
        return jsonify({"ok": False, "error": "Clave SSH almacenada no es válida"}), 400

    client, stored_b64, tofu_policy = _make_ssh_client(_SSH_HOST, ssh_port)
    try:
        client.connect(_SSH_HOST, port=ssh_port, username="root", pkey=key, timeout=15)
        _tofu_persist(stored_b64, tofu_policy)

        # Actualizar PermitRootLogin si existe la directiva, añadirla si no
        harden_cmd = (
            "grep -qE '^\\s*PermitRootLogin' /etc/ssh/sshd_config "
            "&& sed -i 's/^\\s*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config "
            "|| echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config; "
            "systemctl reload sshd && echo 'SSH hardening aplicado'"
        )
        _, stdout, _ = client.exec_command(harden_cmd, timeout=15)
        exit_code = stdout.channel.recv_exit_status()
        output = stdout.read().decode("utf-8", errors="replace").strip()

        if exit_code != 0:
            return jsonify({"ok": False, "error": f"Falló al modificar sshd_config: {output}"}), 500

        AppConfig.set("wf_ssh_hardened", "1")
        return jsonify({"ok": True, "output": output})

    except paramiko.AuthenticationException:
        return jsonify({"ok": False, "error": "Autenticación SSH fallida"}), 401
    except (paramiko.SSHException, OSError) as e:
        return jsonify({"ok": False, "error": f"Error de conexión SSH: {e}"}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        try:
            client.close()
        except Exception:
            pass


# ── WardNode CS ───────────────────────────────────────────────────────

_CS_DURATION_VALUES = {"1h", "24h", "7d", "0s"}
_CS_REASON_RE = re.compile(r"^[\w\-]{1,64}$")


def _cs_required():
    """Returns None if access is allowed, otherwise a redirect response."""
    if AppConfig.get("module_wf_enabled") != "1":
        return redirect(url_for("modules.index"))
    if AppConfig.get("module_cs_enabled") != "1":
        return redirect(url_for("modules.index"))
    return None


@bp.get("/cs/")
@roles_required(ROLE_ADMIN)
def cs_index():
    if (r := _cs_required()):
        return r
    return render_template("modules/cs.html", socket_path=SOCKET_PATH)


@bp.post("/cs/status")
@roles_required(ROLE_ADMIN)
def cs_status():
    if (r := _cs_required()):
        return jsonify({"ok": False, "error": "Módulo CS no habilitado"}), 403
    return jsonify(send_command("cs_status"))


@bp.post("/cs/decisions")
@roles_required(ROLE_ADMIN)
def cs_decisions():
    if (r := _cs_required()):
        return jsonify({"ok": False, "error": "Módulo CS no habilitado"}), 403
    return jsonify(send_command("cs_decisions"))


@bp.post("/cs/ban")
@roles_required(ROLE_ADMIN)
def cs_ban():
    if (r := _cs_required()):
        return jsonify({"ok": False, "error": "Módulo CS no habilitado"}), 403
    ip = request.form.get("ip", "").strip()
    duration = request.form.get("duration", "24h").strip()
    reason = request.form.get("reason", "manual").strip() or "manual"
    if not valid_ip(ip):
        return jsonify({"ok": False, "error": "IP inválida"}), 400
    if duration not in _CS_DURATION_VALUES:
        return jsonify({"ok": False, "error": "Duración inválida"}), 400
    if not _CS_REASON_RE.match(reason):
        return jsonify({"ok": False, "error": "Razón inválida"}), 400
    return jsonify(send_command("cs_ban", ip=ip, duration=duration, reason=reason))


@bp.post("/cs/unban")
@roles_required(ROLE_ADMIN)
def cs_unban():
    if (r := _cs_required()):
        return jsonify({"ok": False, "error": "Módulo CS no habilitado"}), 403
    ip = request.form.get("ip", "").strip()
    if not valid_ip(ip):
        return jsonify({"ok": False, "error": "IP inválida"}), 400
    return jsonify(send_command("cs_unban", ip=ip))


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
    "    resolver 127.0.0.11 valid=10s ipv6=off;\n"
    "\n"
    "    location /obs/ {\n"
    "        modsecurity off;\n"
    "        set $grafana_upstream http://grafana:3000;\n"
    "        proxy_pass         $grafana_upstream$request_uri;\n"
    "        proxy_set_header   Host              $host;\n"
    "        proxy_set_header   X-Real-IP         $remote_addr;\n"
    "        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;\n"
    "        proxy_set_header   X-Forwarded-Proto $scheme;\n"
    "        proxy_set_header   X-WEBAUTH-USER    admin;\n"
    "        proxy_http_version 1.1;\n"
    "        proxy_set_header   Upgrade           $http_upgrade;\n"
    "        proxy_set_header   Connection        \"upgrade\";\n"
    "        proxy_read_timeout 300s;\n"
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

    _OBS_CONTAINERS = ["wardnode-loki", "wardnode-grafana", "wardnode-alloy", "wardnode-prometheus"]

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
                ["docker", "compose", "-f", compose_file, "--profile", "obs", "up", "-d", "--no-build"],
                capture_output=True,
                text=True,
                timeout=120,
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

    # ── Fase 4: inyectar obs.conf en el proxy y recargar ───────────────
    _inject_obs_nginx_conf(client)

    AppConfig.set("module_obs_enabled", "1")
    return jsonify({"ok": True})


@bp.get("/obs/")
@roles_required(ROLE_ADMIN)
def obs_index():
    if (r := _obs_required()):
        return r
    return render_template("modules/obs.html")


@bp.post("/obs/status")
@roles_required(ROLE_ADMIN)
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

    # Re-inyectar obs.conf si el proxy fue reiniciado y lo perdió
    if grafana_ok:
        _inject_obs_nginx_conf(client)

    return jsonify({
        "ok": loki_ok and grafana_ok and alloy_ok and prometheus_ok,
        "loki": loki_ok,
        "grafana": grafana_ok,
        "alloy": alloy_ok,
        "prometheus": prometheus_ok,
    })


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
        "proxy":      "wardnode-proxy"      in running,
        "loki":       "wardnode-loki"       in running,
        "grafana":    "wardnode-grafana"    in running,
        "alloy":      "wardnode-alloy"      in running,
        "prometheus": "wardnode-prometheus" in running,
        "crowdsec":   AppConfig.get("module_cs_enabled") == "1",
        "fluent-bit": "wardnode-fluent-bit" in running,
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
    _DOCKER_TARGETS = {"proxy", "loki", "grafana", "alloy", "prometheus", "fluent-bit"}

    if target == "crowdsec":
        result = send_command("cs_restart_services")
        if result.get("ok"):
            return jsonify({"ok": True})
        return jsonify({"ok": False, "error": result.get("error", "Error al reiniciar CrowdSec")}), 500

    if target in _DOCKER_TARGETS:
        container_name = f"wardnode-{target}"
        try:
            import docker as docker_sdk
            client = docker_sdk.from_env()
            container = client.containers.get(container_name)
            container.restart(timeout=30)
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": False, "error": "Target desconocido"}), 400
