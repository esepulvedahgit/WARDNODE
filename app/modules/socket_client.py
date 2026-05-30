import json
import os
import re
import socket

SOCKET_PATH = os.environ.get("WF_SOCKET_PATH", "/app/sockets/wardnode-wf.sock")
MAX_RESP = 4_194_304  # 4 MB — margen para respuestas grandes del agente WF
TIMEOUT_S = 10

_PORT_RE = re.compile(r"^\d{1,5}$")
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/(?:[12]?\d|3[012]))?$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+(/\d{1,3})?$")
_PROTO = {"tcp", "udp", "any"}
_RULE_RE = re.compile(r"^\d{1,3}$")


def valid_port(p: str) -> bool:
    return bool(_PORT_RE.match(p)) and 1 <= int(p) <= 65535


def valid_ip(ip: str) -> bool:
    if _IPV4_RE.match(ip):
        return all(0 <= int(o) <= 255 for o in ip.split("/")[0].split("."))
    return bool(_IPV6_RE.match(ip))


def valid_proto(p: str) -> bool:
    return p in _PROTO


def valid_rule_num(n: str) -> bool:
    return bool(_RULE_RE.match(n))


def send_command(action: str, timeout: int = TIMEOUT_S, **params) -> dict:
    payload = json.dumps({"action": action, **params}).encode()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(SOCKET_PATH)
            s.sendall(len(payload).to_bytes(4, "big") + payload)
            raw_len = s.recv(4)
            if len(raw_len) < 4:
                return {"ok": False, "error": "Respuesta truncada del agente"}
            resp_len = min(int.from_bytes(raw_len, "big"), MAX_RESP)
            data = b""
            while len(data) < resp_len:
                chunk = s.recv(min(4096, resp_len - len(data)))
                if not chunk:
                    break
                data += chunk
            return json.loads(data.decode())
    except FileNotFoundError:
        return {"ok": False, "error": "Agente WF no disponible (socket no encontrado)"}
    except ConnectionRefusedError:
        return {"ok": False, "error": "Agente WF no disponible (conexión rechazada)"}
    except socket.timeout:
        return {"ok": False, "error": "Timeout comunicando con el agente WF"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
