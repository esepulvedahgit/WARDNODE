"""Control de CrowdSec vía Docker SDK — funciones reutilizables para ban/unban.

Extraído de app/modules/routes.py para ser invocado tanto por las rutas del
módulo DDoS como por el motor SOAR (app/soc/soar.py). La capa de validación
(is_ban_safe) sigue siendo responsabilidad del caller.

El nombre del contenedor CrowdSec se lee de la variable de entorno
WARDNODE_CROWDSEC_CONTAINER (default "wardnode-crowdsec"), coherente con
WARDNODE_PROXY_CONTAINER y WARDNODE_DB_CONTAINER.
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

# R6: configurable via env para coherencia con WARDNODE_PROXY_CONTAINER et al.
_CROWDSEC_CONTAINER = os.environ.get("WARDNODE_CROWDSEC_CONTAINER", "wardnode-crowdsec")


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
        # R5: forma --flag=value elimina ambigüedad de parseo en cobra/pflag (Go)
        exit_code, output = crowdsec_c.exec_run(
            [
                "cscli", "decisions", "add",
                f"--ip={ip}",
                f"--duration={duration}",
                f"--reason={reason}",
                "--type=ban",
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
        # R5: forma --flag=value (consistente con ban_ip)
        exit_code, output = crowdsec_c.exec_run(
            ["cscli", "decisions", "delete", f"--ip={ip}"],
            user="root",
        )
        raw = output.decode("utf-8", errors="replace").strip()
        if exit_code != 0:
            return False, f"cscli error ({exit_code}): {raw[:300]}"
        return True, ""
    except Exception as exc:
        return False, str(exc)
