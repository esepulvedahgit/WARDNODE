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
    return render_template("modules/wf.html", socket_path=SOCKET_PATH)


_SSH_USER_RE = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")
_SSH_HOST = "host.docker.internal"
_AGENT_FILES = [
    "/app/host-agent/wardnode-wf-agent.py",
    "/app/host-agent/wardnode-wf.service",
    "/app/host-agent/wardnode-set-ipv6.sh",
    "/app/host-agent/install.sh",
]


@bp.post("/wf/install")
@roles_required(ROLE_ADMIN)
def wf_install():
    try:
        import paramiko
    except ImportError:
        return jsonify({"ok": False, "error": "Dependencia 'paramiko' no instalada en el contenedor."}), 500

    ssh_host = _SSH_HOST
    ssh_port_raw = request.form.get("ssh_port", "22").strip() or "22"
    ssh_user = "root"
    ssh_key_text = request.form.get("ssh_key", "").strip()

    if not ssh_key_text:
        return jsonify({"ok": False, "error": "Clave SSH requerida"}), 400
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

    tmp_dir = f"/tmp/wardnode_install_{int(time.time())}"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ssh_host, port=ssh_port, username=ssh_user, pkey=key, timeout=15)

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

        _, out, _ = client.exec_command(f"mkdir -p {tmp_dir}")
        out.channel.recv_exit_status()

        sftp = client.open_sftp()
        for local_path in _AGENT_FILES:
            sftp.put(local_path, f"{tmp_dir}/{os.path.basename(local_path)}")
        sftp.close()

        _, stdout, _ = client.exec_command(
            f"cd {tmp_dir} && sudo bash install.sh 2>&1", timeout=120
        )
        exit_code = stdout.channel.recv_exit_status()
        output = stdout.read().decode("utf-8", errors="replace")

        client.exec_command(f"rm -rf {tmp_dir}")

        if exit_code != 0:
            client.close()
            return jsonify({"ok": False, "output": output, "error": f"El script terminó con código {exit_code}"}), 500

        client.close()
        return jsonify({"ok": True, "output": output})

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


# ── WardNode CS ───────────────────────────────────────────────────────

_CS_FILES = [
    "/app/host-agent/wardnode-cs-install.sh",
    "/app/host-agent/sudoers-wardnode-cs",
    "/app/host-agent/wardnode-cs-control.sh",
]

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


@bp.post("/cs/install")
@roles_required(ROLE_ADMIN)
def cs_install():
    if AppConfig.get("module_wf_enabled") != "1":
        return jsonify({"ok": False, "error": "WardNode WF no está activo"}), 403
    if AppConfig.get("module_cs_enabled") != "1":
        return jsonify({"ok": False, "error": "Módulo CS no habilitado"}), 403

    try:
        import paramiko
    except ImportError:
        return jsonify({"ok": False, "error": "Dependencia 'paramiko' no instalada en el contenedor."}), 500

    ssh_host = _SSH_HOST
    ssh_port_raw = request.form.get("ssh_port", "22").strip() or "22"
    ssh_user = "root"
    ssh_key_text = request.form.get("ssh_key", "").strip()

    if not ssh_key_text:
        return jsonify({"ok": False, "error": "Clave SSH requerida"}), 400
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

    tmp_dir = f"/tmp/wardnode_cs_install_{int(time.time())}"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ssh_host, port=ssh_port, username=ssh_user, pkey=key, timeout=15)

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

        _, out, _ = client.exec_command(f"mkdir -p {tmp_dir}")
        out.channel.recv_exit_status()

        sftp = client.open_sftp()
        for local_path in _CS_FILES:
            sftp.put(local_path, f"{tmp_dir}/{os.path.basename(local_path)}")
        sftp.close()

        _, stdout, _ = client.exec_command(
            f"cd {tmp_dir} && sudo bash wardnode-cs-install.sh 2>&1", timeout=180
        )
        exit_code = stdout.channel.recv_exit_status()
        output = stdout.read().decode("utf-8", errors="replace")

        client.exec_command(f"rm -rf {tmp_dir}")

        if exit_code != 0:
            client.close()
            return jsonify({"ok": False, "output": output, "error": f"El script terminó con código {exit_code}"}), 500

        client.close()
        return jsonify({"ok": True, "output": output})

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


@bp.post("/obs/activate")
@roles_required(ROLE_ADMIN)
def obs_activate():
    import os
    import subprocess
    import time
    import urllib.request as _ur

    try:
        import docker as docker_sdk
    except ImportError:
        return jsonify({"ok": False, "step": "docker", "error": "SDK de Docker no instalado en el contenedor"}), 500

    _OBS_CONTAINERS = ["wardnode-loki", "wardnode-grafana", "wardnode-fluent-bit"]

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
                    "Añádela al archivo .env.prod apuntando al directorio del proyecto "
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

    # ── Fase 3: esperar a que los servicios estén listos (máx 90 s) ───────
    loki_ok = False
    grafana_ok = False
    fluentbit_ok = False
    deadline = time.time() + 90

    while time.time() < deadline:
        if not loki_ok:
            try:
                with _ur.urlopen("http://loki:3100/ready", timeout=3) as r:
                    loki_ok = r.status == 200
            except Exception:
                pass
        if not grafana_ok:
            try:
                with _ur.urlopen("http://grafana:3000/api/health", timeout=3) as r:
                    grafana_ok = r.status == 200
            except Exception:
                pass
        if not fluentbit_ok:
            try:
                with _ur.urlopen("http://fluent-bit:2020/api/v1/health", timeout=3) as r:
                    fluentbit_ok = r.status == 200
            except Exception:
                pass
        if loki_ok and grafana_ok and fluentbit_ok:
            break
        time.sleep(3)

    not_ready = [
        s for s, ok in [("Loki", loki_ok), ("Grafana", grafana_ok), ("Fluent Bit", fluentbit_ok)]
        if not ok
    ]
    if not_ready:
        svc = " y ".join(not_ready)
        return jsonify({
            "ok": False,
            "step": "health",
            "error": (
                f"{svc} no responde{'n' if len(not_ready) > 1 else ''} después de 90 s. "
                "Los contenedores pueden estar arrancando lentamente en el primer inicio. "
                "Espera unos segundos y vuelve a intentarlo."
            ),
        }), 500

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
        return jsonify({"ok": False, "loki": False, "grafana": False, "fluentbit": False, "error": "Módulo OBS no habilitado"}), 403
    import urllib.request as _ur
    loki_ok = False
    grafana_ok = False
    fluentbit_ok = False
    try:
        with _ur.urlopen("http://loki:3100/ready", timeout=5) as r:
            loki_ok = r.status == 200
    except Exception:
        pass
    try:
        with _ur.urlopen("http://grafana:3000/api/health", timeout=5) as r:
            grafana_ok = r.status == 200
    except Exception:
        pass
    try:
        with _ur.urlopen("http://fluent-bit:2020/api/v1/health", timeout=5) as r:
            fluentbit_ok = r.status == 200
    except Exception:
        pass
    return jsonify({"ok": loki_ok and grafana_ok and fluentbit_ok, "loki": loki_ok, "grafana": grafana_ok, "fluentbit": fluentbit_ok})
