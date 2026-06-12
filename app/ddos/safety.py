"""Guardas de seguridad para ban/unban manual en el módulo DDoS.

is_ban_safe() evalúa si es seguro aplicar un ban a una IP antes de llamar
a cscli. Aplica cinco capas de protección para evitar auto-bloqueo o pérdida
de acceso de administración.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Iterable, Tuple


# ── Helpers de normalización ───────────────────────────────────────────────


def _norm(value: str) -> str | None:
    """Devuelve la forma canónica de una IP, o None si el string no es una IP válida."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _norm_set(raw_items: Iterable[str]) -> set[str]:
    """Normaliza un iterable de strings de IP, descartando entradas inválidas."""
    return {n for n in (_norm(x) for x in raw_items) if n}


# ── Guardas auxiliares ─────────────────────────────────────────────────────


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
    """Enumera las IPs propias del host (best-effort — no lanza excepciones).

    Estrategia de doble fuente:
    1. UDP connect trick: abre un socket UDP hacia una dirección pública (sin enviar
       tráfico) para que el SO resuelva la interfaz de salida. Devuelve la IP pública
       real del host, incluso dentro de un contenedor con network_mode: host.
    2. getaddrinfo(hostname): complemento para entornos donde el truco UDP falla
       (ej. hosts sin ruta a internet), cubre loopback y alias locales.

    Devuelve strings en forma canónica (ipaddress) para comparación segura.
    """
    ips: set[str] = set()

    # Método 1: IP de salida real (no envía paquetes)
    for family, dst in (
        (socket.AF_INET,  "1.1.1.1"),
        (socket.AF_INET6, "2606:4700:4700::1111"),
    ):
        try:
            s = socket.socket(family, socket.SOCK_DGRAM)
            s.connect((dst, 80))
            raw_ip = s.getsockname()[0]
            s.close()
            norm = _norm(raw_ip)
            if norm:
                ips.add(norm)
        except OSError:
            pass

    # Método 2: hostname → getaddrinfo (fallback)
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            norm = _norm(info[4][0])
            if norm:
                ips.add(norm)
    except OSError:
        pass

    return ips


# ── Función principal ──────────────────────────────────────────────────────


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

    # Forma canónica normalizada — se usa en todas las comparaciones siguientes
    norm = str(addr)

    # ── Guardia 1: no banear la IP del propio administrador ───────────────
    # Normalizamos request_ip también para evitar bypass por forma equivalente
    if norm == _norm(request_ip):
        return False, "No puedes banear tu propia dirección IP — perderías acceso al panel."

    # ── Guardia 2: rangos reservados / privados / loopback / Docker ───────
    # 172.16.0.0/12 cubre la subred interna Docker (172.17–172.30.x.x)
    # Esta guardia usa el objeto addr normalizado por ipaddress — es robusta por diseño.
    if _is_protected_range(addr):
        return False, (
            f"La IP {ip} pertenece a un rango reservado o privado "
            "(loopback, RFC-1918, red Docker) y no puede ser baneada."
        )

    # ── Guardia 3: IPs propias del host (interfaces de red) ───────────────
    # _host_ips() ya devuelve formas canónicas; norm también lo está.
    if norm in _host_ips():
        return False, f"La IP {ip} corresponde a una interfaz del propio servidor y no puede ser baneada."

    # ── Guardia 4: host de gestión SSH almacenado en AppConfig ────────────
    ssh_host = (AppConfig.get("wf_ssh_host") or "").strip()
    if ssh_host and (sh_norm := _norm(ssh_host)) and norm == sh_norm:
        return False, (
            f"La IP {ip} es el host de gestión SSH configurado. "
            "Elimínala del campo 'Host SSH' en Ajustes antes de banearla."
        )

    # ── Guardia 5: allowlist editable (AppConfig["ddos_safe_ips"], CSV) ───
    # Permite al administrador proteger IPs de la consola, proxy u otras.
    # _norm_set normaliza el lado de la allowlist para evitar bypass por forma equivalente.
    safe_list_raw = AppConfig.get("ddos_safe_ips") or ""
    safe_items = (s for s in safe_list_raw.split(",") if s.strip())
    if norm in _norm_set(safe_items):
        return False, (
            f"La IP {ip} está en la lista de IPs protegidas. "
            "Edítala en el panel del módulo CrowdSec si deseas eliminarla."
        )

    return True, ""
