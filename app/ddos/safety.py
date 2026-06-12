"""Guardas de seguridad para ban/unban manual en el módulo DDoS.

is_ban_safe() evalúa si es seguro aplicar un ban a una IP antes de llamar
a cscli. Aplica cuatro capas de protección para evitar auto-bloqueo o pérdida
de acceso de administración.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Tuple


def _is_protected_range(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True si la IP pertenece a rangos reservados/privados que nunca deben banearse."""
    return (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_unspecified
        or addr.is_multicast
    )


def _host_ips() -> set[str]:
    """Enumera las IPs propias del host (best-effort — no lanza excepciones)."""
    try:
        hostname = socket.gethostname()
        infos = socket.getaddrinfo(hostname, None)
        return {info[4][0] for info in infos}
    except Exception:
        return set()


def is_ban_safe(ip: str, request_ip: str) -> Tuple[bool, str]:
    """Evalúa si es seguro banear `ip`.

    Args:
        ip: dirección IP que se quiere banear (formato texto, sin CIDR).
        request_ip: IP de origen del administrador que realiza la petición.

    Returns:
        (True, "")        — ban seguro, puede ejecutarse.
        (False, motivo)   — ban rechazado, motivo legible para el usuario.
    """
    # Importaciones locales para evitar circular imports al usar en rutas Flask
    from app.models import AppConfig

    ip = ip.strip()
    request_ip = (request_ip or "").strip()

    # ── Guardia 0: formato válido (no se aceptan CIDRs en bans manuales) ──
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, "Dirección IP inválida. Los bans manuales aceptan IPs individuales, no rangos CIDR."

    # ── Guardia 1: no banear la IP del propio administrador ───────────────
    if ip == request_ip:
        return False, "No puedes banear tu propia dirección IP — perderías acceso al panel."

    # ── Guardia 2: rangos reservados / privados / loopback / Docker ───────
    # 172.16.0.0/12 cubre la subred interna Docker (172.17–172.30.x.x)
    if _is_protected_range(addr):
        return False, (
            f"La IP {ip} pertenece a un rango reservado o privado "
            "(loopback, RFC-1918, red Docker) y no puede ser baneada."
        )

    # ── Guardia 3: IPs propias del host (interfaces de red) ───────────────
    if ip in _host_ips():
        return False, f"La IP {ip} corresponde a una interfaz del propio servidor y no puede ser baneada."

    # ── Guardia 4: host de gestión SSH almacenado en AppConfig ────────────
    ssh_host = (AppConfig.get("wf_ssh_host") or "").strip()
    if ssh_host and ip == ssh_host:
        return False, (
            f"La IP {ip} es el host de gestión SSH configurado. "
            "Elimínala del campo 'Host SSH' en Ajustes antes de banearla."
        )

    # ── Guardia 5: allowlist editable (AppConfig["ddos_safe_ips"], CSV) ───
    # Permite al administrador proteger IPs de la consola, proxy u otras.
    safe_list_raw = AppConfig.get("ddos_safe_ips") or ""
    safe_ips = {s.strip() for s in safe_list_raw.split(",") if s.strip()}
    if ip in safe_ips:
        return False, (
            f"La IP {ip} está en la lista de IPs protegidas. "
            "Edítala en el panel del módulo CrowdSec si deseas eliminarla."
        )

    return True, ""
