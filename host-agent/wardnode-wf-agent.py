#!/usr/bin/env python3
"""WardNode WF Agent — escucha Unix socket, ejecuta ufw con privilegios mínimos."""
import json
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import sys

SOCKET_PATH = "/run/wardnode/wardnode-wf.sock"
SOCKET_DIR = os.path.dirname(SOCKET_PATH)
MAX_PAYLOAD = 4_096
TIMEOUT_S = 10
_SECURE_PORT_MARKER = "/opt/wardnode/.secure_port5000"
_PROTECTED_PORTS_MARKER = "/opt/wardnode/.protected_ports.json"
_BLOCKED_PORTS = {22, 80, 443, 5000}
_DOCKER_CIDR = "172.16.0.0/12"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [wf-agent] %(levelname)s %(message)s",
)

_PORT_RE = re.compile(r"^\d{1,5}$")
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/(?:[12]?\d|3[012]))?$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+(/\d{1,3})?$")
_PROTO = {"tcp", "udp", "any"}
_RULE_RE = re.compile(r"^\d{1,3}$")
ACTIONS = {"status", "allow_port", "deny_port", "allow_ip", "deny_ip", "delete_rule",
           "check_defaults", "init_firewall",
           "get_ipv6_status", "set_ipv6",
           "secure_console_port",
           "protect_host_port", "unprotect_host_port",
           "list_docker_ports",
           "limit_port", "unlimit_port"}


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


def _enable_ufw_logging() -> dict:
    result = _ufw("logging", "medium")
    try:
        open("/var/log/ufw.log", "a", encoding="utf-8").close()
        os.chmod("/var/log/ufw.log", 0o640)
    except Exception:
        pass
    return result


def _iptables(*args) -> dict:
    try:
        r = subprocess.run(
            ["/usr/sbin/iptables", *args],
            capture_output=True, text=True, timeout=10,
        )
        return {"ok": r.returncode == 0, "output": (r.stdout or r.stderr).strip()}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "iptables timeout"}
    except FileNotFoundError:
        return {"ok": False, "error": "iptables no encontrado"}


def _load_protected_ports() -> dict:
    try:
        with open(_PROTECTED_PORTS_MARKER, encoding="utf-8") as fh:
            data = json.load(fh)
            return {str(k): bool(v) for k, v in data.items()}
    except (FileNotFoundError, json.JSONDecodeError, Exception):
        return {}


def _save_protected_ports(ports: dict) -> None:
    try:
        os.makedirs(os.path.dirname(_PROTECTED_PORTS_MARKER), exist_ok=True)
        with open(_PROTECTED_PORTS_MARKER, "w", encoding="utf-8") as fh:
            json.dump(ports, fh)
    except Exception as exc:
        logging.warning(f"No se pudo guardar marcador de puertos protegidos: {exc}")


def _protect_host_port(port: str) -> dict:
    """Bloquea acceso externo al puerto del host vía raw/PREROUTING.
    Añade excepción loopback (-i lo) para permitir que el proxy en host network alcance el upstream.
    """
    # Idempotencia: borrar reglas previas para este puerto
    for rule in [
        ["-t", "raw", "-D", "PREROUTING", "-i", "lo", "-p", "tcp", "--dport", port, "-j", "ACCEPT"],
        ["-t", "raw", "-D", "PREROUTING", "-p", "tcp", "--dport", port, "!", "-s", _DOCKER_CIDR, "-j", "DROP"],
    ]:
        for _ in range(10):
            r = subprocess.run(["/usr/sbin/iptables"] + rule,
                               capture_output=True, text=True, timeout=5)
            if r.returncode != 0:
                break

    # Insertar DROP en pos 1, luego lo ACCEPT en pos 1 → ACCEPT queda primero
    result = _iptables("-t", "raw", "-I", "PREROUTING", "1",
                       "-p", "tcp", "--dport", port,
                       "!", "-s", _DOCKER_CIDR, "-j", "DROP")
    if not result["ok"]:
        return {"ok": False, "error": f"iptables: {result['output']}"}

    result = _iptables("-t", "raw", "-I", "PREROUTING", "1",
                       "-i", "lo", "-p", "tcp", "--dport", port, "-j", "ACCEPT")
    if not result["ok"]:
        return {"ok": False, "error": f"iptables lo ACCEPT: {result['output']}"}

    ports = _load_protected_ports()
    ports[port] = True
    _save_protected_ports(ports)
    return {"ok": True, "output": f"Puerto {port} asegurado: acceso externo bloqueado vía raw/PREROUTING"}


def _unprotect_host_port(port: str) -> dict:
    """Elimina las reglas raw/PREROUTING (DROP y lo ACCEPT) que protegen el puerto del host."""
    removed = 0
    for rule in [
        ["-t", "raw", "-D", "PREROUTING", "-i", "lo", "-p", "tcp", "--dport", port, "-j", "ACCEPT"],
        ["-t", "raw", "-D", "PREROUTING", "-p", "tcp", "--dport", port, "!", "-s", _DOCKER_CIDR, "-j", "DROP"],
    ]:
        for _ in range(10):
            r = subprocess.run(["/usr/sbin/iptables"] + rule,
                               capture_output=True, text=True, timeout=5)
            if r.returncode != 0:
                break
            removed += 1

    ports = _load_protected_ports()
    ports.pop(port, None)
    _save_protected_ports(ports)
    return {"ok": True, "output": f"Puerto {port} desprotegido ({removed} reglas eliminadas)"}


def _restore_protected_ports_if_needed() -> None:
    """Re-aplica reglas INPUT al arrancar para cada puerto en el marcador JSON."""
    ports = _load_protected_ports()
    for port, active in ports.items():
        if not active:
            continue
        logging.info(f"Restaurando bloqueo del puerto {port} en INPUT")
        result = _protect_host_port(port)
        if result.get("ok"):
            logging.info(f"Puerto {port} bloqueado correctamente al arrancar")
        else:
            logging.warning(f"No se pudo restaurar bloqueo del puerto {port}: {result.get('error', '')}")


def _secure_console_port() -> dict:
    """Bloquea acceso externo al puerto 5000 vía cadena INPUT de iptables.
    Permite loopback (proxy en host network) y bloquea el resto.
    """
    # Idempotencia: eliminar reglas previas para el puerto 5000 en INPUT
    for rule in [
        ["-D", "INPUT", "-p", "tcp", "--dport", "5000", "-j", "DROP"],
        ["-D", "INPUT", "-i", "lo", "-p", "tcp", "--dport", "5000", "-j", "ACCEPT"],
    ]:
        for _ in range(10):
            r = subprocess.run(
                ["/usr/sbin/iptables"] + rule,
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode != 0:
                break

    # Insertar DROP primero, luego lo ACCEPT al frente → ACCEPT queda en posición 1
    for rule in [
        ["-I", "INPUT", "1", "-p", "tcp", "--dport", "5000", "-j", "DROP"],
        ["-I", "INPUT", "1", "-i", "lo", "-p", "tcp", "--dport", "5000", "-j", "ACCEPT"],
    ]:
        result = _iptables(*rule)
        if not result["ok"]:
            return {"ok": False, "error": f"iptables: {result['output']}"}

    try:
        os.makedirs(os.path.dirname(_SECURE_PORT_MARKER), exist_ok=True)
        with open(_SECURE_PORT_MARKER, "w", encoding="utf-8") as fh:
            fh.write("secured\n")
    except Exception as exc:
        logging.warning(f"No se pudo escribir marcador de persistencia: {exc}")

    return {"ok": True, "output": "Puerto 5000 asegurado: acceso externo bloqueado vía INPUT"}


def _restore_secure_port_if_needed() -> None:
    """Re-aplica reglas INPUT al arrancar si el marcador de persistencia existe."""
    if not os.path.exists(_SECURE_PORT_MARKER):
        return
    logging.info("Marcador encontrado — restaurando bloqueo del puerto 5000 en INPUT")
    result = _secure_console_port()
    if result.get("ok"):
        logging.info("Puerto 5000 bloqueado correctamente al arrancar")
    else:
        logging.warning(f"No se pudo restaurar bloqueo del puerto 5000: {result.get('error', '')}")


_PORT_MAPPING_RE = re.compile(r"([\d.]+|[\da-fA-F:]+):(\d+)->(\d+)/(tcp|udp)")


def _is_host_port_blocked(port: str) -> bool:
    """Verifica si la regla raw/PREROUTING de bloqueo existe en iptables (fuente de verdad real)."""
    r = subprocess.run(
        ["/usr/sbin/iptables", "-t", "raw", "-C", "PREROUTING",
         "-p", "tcp", "--dport", port, "!", "-s", _DOCKER_CIDR, "-j", "DROP"],
        capture_output=True, text=True, timeout=5,
    )
    return r.returncode == 0


def _docker_bin() -> str | None:
    """Localiza el binario docker considerando instalaciones snap y rutas no estándar."""
    candidate = shutil.which("docker")
    if candidate:
        return candidate
    for path in ("/usr/bin/docker", "/usr/local/bin/docker", "/snap/bin/docker"):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _list_docker_ports() -> dict:
    """Lista puertos publicados de contenedores Docker activos con su estado de bloqueo."""
    docker = _docker_bin()
    if not docker:
        return {"ok": False, "error": "docker no encontrado — ¿está instalado en el host?"}

    try:
        r = subprocess.run(
            [docker, "ps", "--format", '{"name":"{{.Names}}","ports":"{{.Ports}}"}'],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            return {"ok": False, "error": f"docker ps falló: {r.stderr.strip()}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Timeout al ejecutar docker ps"}

    seen: set[tuple] = set()
    ports_list = []
    for line in r.stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        for m in _PORT_MAPPING_RE.finditer(item.get("ports", "")):
            host_ip = m.group(1)
            host_port = m.group(2)
            container_port = m.group(3)
            proto = m.group(4)
            loopback_only = host_ip in ("127.0.0.1", "::1")
            key = (item.get("name", ""), host_port, proto)
            if key in seen:
                continue
            seen.add(key)
            ports_list.append({
                "container": item.get("name", ""),
                "host_port": host_port,
                "container_port": container_port,
                "proto": proto,
                "loopback_only": loopback_only,
                "blocked": False if loopback_only else _is_host_port_blocked(host_port),
            })

    return {"ok": True, "ports": ports_list, "raw": r.stdout.strip()}


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
            # Permitir que los contenedores del bridge Docker (172.16/12) alcancen
            # el endpoint interno stub_status (:8081) del proxy. Sin esta regla,
            # UFW default-deny bloquea el tráfico del nginx-exporter y los paneles
            # nginx_* de Grafana quedan vacíos. La regla es segura: 00-stub-status.conf
            # cierra con `allow 172.16.0.0/12; deny all;` a nivel nginx.
            _ufw("allow", "from", "172.16.0.0/12", "to", "any", "port", "8081", "proto", "tcp"),
            _enable_ufw_logging(),
            _ufw("--force", "enable"),
        ]
        output = "\n".join(s.get("output", "") for s in steps)
        ok = all(s.get("ok") for s in steps)
        return {"ok": ok, "output": output}

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

    if action == "secure_console_port":
        return _secure_console_port()

    if action == "protect_host_port":
        port = str(cmd.get("port", ""))
        if not _vport(port):
            return {"ok": False, "error": "Puerto inválido"}
        if int(port) in _BLOCKED_PORTS:
            return {"ok": False, "error": f"El puerto {port} está reservado y no puede bloquearse"}
        return _protect_host_port(port)

    if action == "unprotect_host_port":
        port = str(cmd.get("port", ""))
        if not _vport(port):
            return {"ok": False, "error": "Puerto inválido"}
        return _unprotect_host_port(port)

    if action == "list_docker_ports":
        return _list_docker_ports()

    if action == "limit_port":
        port = str(cmd.get("port", "22"))
        proto = str(cmd.get("proto", "tcp"))
        if not _vport(port):
            return {"ok": False, "error": "Puerto inválido"}
        if not _vproto(proto):
            return {"ok": False, "error": "Protocolo inválido"}
        return _ufw("limit", f"{port}/{proto}")

    if action == "unlimit_port":
        port = str(cmd.get("port", "22"))
        proto = str(cmd.get("proto", "tcp"))
        if not _vport(port):
            return {"ok": False, "error": "Puerto inválido"}
        if not _vproto(proto):
            return {"ok": False, "error": "Protocolo inválido"}
        _ufw("delete", "limit", f"{port}/{proto}")
        return _ufw("allow", f"{port}/{proto}")

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
    _restore_secure_port_if_needed()
    _restore_protected_ports_if_needed()
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
                try:
                    conn.sendall(len(resp_bytes).to_bytes(4, "big") + resp_bytes)
                except Exception as exc:
                    logging.warning("Error enviando respuesta (cliente desconectado): %s", exc)


if __name__ == "__main__":
    serve()
