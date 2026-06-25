"""Control de CrowdSec vía Docker SDK — funciones reutilizables para ban/unban.

Extraído de app/modules/routes.py para ser invocado tanto por las rutas del
módulo DDoS como por el motor SOAR (app/soc/soar.py). La capa de validación
(is_ban_safe) sigue siendo responsabilidad del caller.

El nombre del contenedor CrowdSec puede configurarse a futuro via env; por ahora
está hardcodeado al mismo valor que usa la UI: "wardnode-crowdsec".
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)

_CROWDSEC_CONTAINER = "wardnode-crowdsec"


def ban_ip(ip: str, duration: str = "24h", reason: str = "manual-ban") -> tuple[bool, str]:
    """Ejecuta `cscli decisions add` en el contenedor CrowdSec.

    Args:
        ip:       IP individual a banear (ya validada y pasada por is_ban_safe).
        duration: Duración del ban, formato r'^\\d+[smhd]$' (ej. "24h", "7d").
        reason:   Razon del ban, formato r'^[\\w-]{1,64}$'.

    Returns:
        (True, "")             — ban aplicado.
        (False, msg_error)     — cscli o Docker falló; msg para log.
    """
    try:
        import docker as docker_sdk

        client = docker_sdk.from_env()
        crowdsec_c = client.containers.get(_CROWDSEC_CONTAINER)
        exit_code, output = crowdsec_c.exec_run(
            [
                "cscli", "decisions", "add",
                "--ip", ip,
                "--duration", duration,
                "--reason", reason,
                "--type", "ban",
            ],
            user="root",
        )
        raw = output.decode("utf-8", errors="replace").strip()
        if exit_code != 0:
            return False, f"cscli error ({exit_code}): {raw[:300]}"
        return True, ""
    except Exception as exc:
        return False, str(exc)


def unban_ip(ip: str) -> tuple[bool, str]:
    """Ejecuta `cscli decisions delete` en el contenedor CrowdSec.

    Args:
        ip: IP individual a desbanear.

    Returns:
        (True, "")             — decision eliminada.
        (False, msg_error)     — cscli o Docker falló.
    """
    try:
        import docker as docker_sdk

        client = docker_sdk.from_env()
        crowdsec_c = client.containers.get(_CROWDSEC_CONTAINER)
        exit_code, output = crowdsec_c.exec_run(
            ["cscli", "decisions", "delete", "--ip", ip],
            user="root",
        )
        raw = output.decode("utf-8", errors="replace").strip()
        if exit_code != 0:
            return False, f"cscli error ({exit_code}): {raw[:300]}"
        return True, ""
    except Exception as exc:
        return False, str(exc)
