#!/usr/bin/env python3
"""WardNode WF Agent — escucha Unix socket, ejecuta ufw con privilegios mínimos."""
import json
import logging
import os
import re
import signal
import socket
import subprocess
import sys

SOCKET_PATH = "/run/wardnode/wardnode-wf.sock"
SOCKET_DIR = os.path.dirname(SOCKET_PATH)
MAX_PAYLOAD = 4_096
TIMEOUT_S = 10

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [wf-agent] %(levelname)s %(message)s",
)

_PORT_RE = re.compile(r"^\d{1,5}$")
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/(?:[12]?\d|3[012]))?$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+(/\d{1,3})?$")
_PROTO = {"tcp", "udp", "any"}
_RULE_RE = re.compile(r"^\d{1,3}$")
_DURATION_RE = re.compile(r"^\d+[smhd]$")
_REASON_RE = re.compile(r"^[\w\-]{1,64}$")
ACTIONS = {"status", "allow_port", "deny_port", "allow_ip", "deny_ip", "delete_rule",
           "check_defaults", "init_firewall",
           "cs_status", "cs_decisions", "cs_ban", "cs_unban",
           "cs_stop_services", "cs_start_services", "cs_restart_services",
           "get_ipv6_status", "set_ipv6"}


def _vport(p):
    return bool(_PORT_RE.match(str(p))) and 1 <= int(p) <= 65535


def _vip(ip):
    s = str(ip)
    if _IPV4_RE.match(s):
        return all(0 <= int(o) <= 255 for o in s.split("/")[0].split("."))
    return bool(_IPV6_RE.match(s))


def _vproto(p):
    return str(p) in _PROTO


def _vrule(n):
    return bool(_RULE_RE.match(str(n)))


def _cscli(*args) -> dict:
    try:
        r = subprocess.run(
            ["/usr/bin/cscli", *args],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return {"ok": r.returncode == 0, "output": (r.stdout or r.stderr).strip()}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "cscli timeout"}
    except FileNotFoundError:
        return {"ok": False, "error": "cscli no encontrado — ¿CrowdSec instalado?"}


def _ufw(*args) -> dict:
    try:
        r = subprocess.run(
            ["/usr/sbin/ufw", *args],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return {"ok": r.returncode == 0, "output": (r.stdout or r.stderr).strip()}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "ufw timeout"}


def handle(cmd: dict) -> dict:
    action = cmd.get("action", "")
    if action not in ACTIONS:
        return {"ok": False, "error": "Acción no permitida"}

    if action == "status":
        return _ufw("status", "numbered")

    if action == "allow_port":
        port, proto = str(cmd.get("port", "")), str(cmd.get("proto", "tcp"))
        if not _vport(port):
            return {"ok": False, "error": "Puerto inválido"}
        if not _vproto(proto):
            return {"ok": False, "error": "Protocolo inválido"}
        rule = port if proto == "any" else f"{port}/{proto}"
        return _ufw("allow", rule)

    if action == "deny_port":
        port, proto = str(cmd.get("port", "")), str(cmd.get("proto", "tcp"))
        if not _vport(port):
            return {"ok": False, "error": "Puerto inválido"}
        if not _vproto(proto):
            return {"ok": False, "error": "Protocolo inválido"}
        rule = port if proto == "any" else f"{port}/{proto}"
        return _ufw("deny", rule)

    if action == "allow_ip":
        ip = str(cmd.get("ip", ""))
        if not _vip(ip):
            return {"ok": False, "error": "IP inválida"}
        return _ufw("allow", "from", ip)

    if action == "deny_ip":
        ip = str(cmd.get("ip", ""))
        if not _vip(ip):
            return {"ok": False, "error": "IP inválida"}
        return _ufw("deny", "from", ip)

    if action == "delete_rule":
        num = str(cmd.get("rule_num", ""))
        if not _vrule(num):
            return {"ok": False, "error": "Número de regla inválido"}
        return _ufw("--force", "delete", num)

    if action == "check_defaults":
        return _ufw("status", "verbose")

    if action == "init_firewall":
        ssh_port = str(cmd.get("ssh_port", "22"))
        if not _vport(ssh_port):
            return {"ok": False, "error": "Puerto SSH inválido"}
        steps = [
            _ufw("default", "deny", "incoming"),
            _ufw("default", "allow", "outgoing"),
            _ufw("allow", f"{ssh_port}/tcp"),
            _ufw("allow", "80/tcp"),
            _ufw("allow", "443/tcp"),
            _ufw("--force", "enable"),
        ]
        output = "\n".join(s.get("output", "") for s in steps)
        ok = all(s.get("ok") for s in steps)
        return {"ok": ok, "output": output}

    if action == "cs_status":
        version = _cscli("version")
        if not version.get("ok"):
            return {"ok": False, "error": version.get("error", "CrowdSec no disponible — reinstala el agente WF desde el panel")}
        svc = subprocess.run(
            ["systemctl", "is-active", "crowdsec"],
            capture_output=True, text=True,
        ).stdout.strip()
        bouncer = subprocess.run(
            ["systemctl", "is-active", "crowdsec-firewall-bouncer"],
            capture_output=True, text=True,
        ).stdout.strip()
        return {
            "ok": True,
            "output": version.get("output", ""),
            "crowdsec": svc,
            "bouncer": bouncer,
        }

    if action == "cs_decisions":
        return _cscli("decisions", "list", "-o", "json")

    if action == "cs_ban":
        ip = str(cmd.get("ip", ""))
        duration = str(cmd.get("duration", "24h"))
        reason = str(cmd.get("reason", "manual"))
        if not _vip(ip):
            return {"ok": False, "error": "IP inválida"}
        if not _DURATION_RE.match(duration):
            return {"ok": False, "error": "Duración inválida (ej: 24h, 7d, 3600s)"}
        if not _REASON_RE.match(reason):
            return {"ok": False, "error": "Razón inválida (solo letras, números, guiones)"}
        return _cscli("decisions", "add", "--ip", ip,
                      "--duration", duration, "--reason", reason, "--type", "ban")

    if action == "cs_unban":
        ip = str(cmd.get("ip", ""))
        if not _vip(ip):
            return {"ok": False, "error": "IP inválida"}
        return _cscli("decisions", "delete", "--ip", ip)

    if action in ("cs_stop_services", "cs_start_services"):
        stopping = action == "cs_stop_services"
        steps = (
            [("stop", "bouncer"), ("stop", "crowdsec"), ("disable", "bouncer"), ("disable", "crowdsec")]
            if stopping else
            [("enable", "crowdsec"), ("start", "crowdsec"), ("enable", "bouncer"), ("start", "bouncer")]
        )
        outputs = []
        for act, tgt in steps:
            try:
                r = subprocess.run(
                    ["/opt/wardnode/wardnode-cs-control.sh", act, tgt],
                    capture_output=True, text=True, timeout=15,
                )
                outputs.append((r.stdout or r.stderr).strip())
                if r.returncode != 0:
                    return {"ok": False, "error": f"Fallo en '{act} {tgt}'", "output": "\n".join(outputs)}
            except subprocess.TimeoutExpired:
                return {"ok": False, "error": f"Timeout al ejecutar '{act} {tgt}'"}
            except FileNotFoundError:
                return {"ok": False, "error": "Script de control CS no encontrado — reinstala el agente WF"}
        return {"ok": True, "output": "\n".join(o for o in outputs if o)}

    if action == "cs_restart_services":
        outputs = []
        for tgt in ["crowdsec", "bouncer"]:
            try:
                r = subprocess.run(
                    ["/opt/wardnode/wardnode-cs-control.sh", "restart", tgt],
                    capture_output=True, text=True, timeout=30,
                )
                outputs.append((r.stdout or r.stderr).strip())
                if r.returncode != 0:
                    return {"ok": False, "error": f"Fallo al reiniciar '{tgt}'", "output": "\n".join(outputs)}
            except subprocess.TimeoutExpired:
                return {"ok": False, "error": f"Timeout al reiniciar '{tgt}'"}
            except FileNotFoundError:
                return {"ok": False, "error": "Script de control CS no encontrado — reinstala el agente WF"}
        return {"ok": True, "output": "\n".join(o for o in outputs if o)}

    if action == "get_ipv6_status":
        try:
            with open("/etc/default/ufw") as f:
                for line in f:
                    if line.startswith("IPV6="):
                        val = line.strip().split("=", 1)[1].strip().lower()
                        return {"ok": True, "ipv6": val == "yes"}
            return {"ok": True, "ipv6": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    if action == "set_ipv6":
        enabled = cmd.get("enabled")
        if not isinstance(enabled, bool):
            return {"ok": False, "error": "Campo 'enabled' debe ser booleano"}
        val = "yes" if enabled else "no"
        try:
            r = subprocess.run(
                ["/opt/wardnode/wardnode-set-ipv6.sh", val],
                capture_output=True, text=True, timeout=20,
            )
            return {"ok": r.returncode == 0, "output": (r.stdout or r.stderr).strip()}
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "Timeout al configurar IPv6"}
        except FileNotFoundError:
            return {"ok": False, "error": "Script IPv6 no encontrado — ejecuta install.sh nuevamente"}

    return {"ok": False, "error": "Sin handler"}


def _ensure_ufw_active() -> None:
    try:
        r = subprocess.run(
            ["/usr/sbin/ufw", "status"],
            capture_output=True, text=True, timeout=10,
        )
        output = (r.stdout or r.stderr).strip()
        lines = [l for l in output.splitlines() if l.strip()]
        summary = lines[0] if lines else '(sin output)'
        logging.info(f"UFW status al iniciar: {summary}")
    except FileNotFoundError:
        logging.error("UFW no encontrado en /usr/sbin/ufw — instálalo con: apt install ufw")
    except subprocess.TimeoutExpired:
        logging.error("Timeout al verificar UFW.")
    except Exception as exc:
        logging.error(f"Error verificando UFW: {exc}")


def serve():
    _ensure_ufw_active()
    os.makedirs(SOCKET_DIR, exist_ok=True)
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
        srv.bind(SOCKET_PATH)
        os.chmod(SOCKET_PATH, 0o660)
        srv.listen(5)
        logging.info(f"Escuchando en {SOCKET_PATH}")

        def _shutdown(sig, _):
            logging.info("Señal recibida, cerrando.")
            if os.path.exists(SOCKET_PATH):
                os.unlink(SOCKET_PATH)
            sys.exit(0)

        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT, _shutdown)

        while True:
            conn, _ = srv.accept()
            with conn:
                conn.settimeout(TIMEOUT_S)
                try:
                    raw_len = conn.recv(4)
                    if len(raw_len) < 4:
                        continue
                    plen = int.from_bytes(raw_len, "big")
                    if plen > MAX_PAYLOAD:
                        logging.warning(f"Payload oversized: {plen} bytes — rechazado")
                        continue
                    data = conn.recv(plen)
                    cmd = json.loads(data.decode())
                    logging.info(f"CMD recibido: action={cmd.get('action')}")
                    resp = handle(cmd)
                except Exception as exc:
                    logging.error(f"Error procesando comando: {exc}")
                    resp = {"ok": False, "error": "Comando malformado"}

                resp_bytes = json.dumps(resp).encode()
                conn.sendall(len(resp_bytes).to_bytes(4, "big") + resp_bytes)


if __name__ == "__main__":
    serve()
