"""Política central de contraseñas de WardNode.

Fuente única de verdad compartida por el backend (routes) y los tests.
El frontend (Alpine.js) espeja exactamente los mismos 5 requisitos.
"""
from __future__ import annotations

import re

MIN_LENGTH = 12

# Cada tupla: (id_frontend, etiqueta visible al usuario, función de test)
# El id_frontend se referencia en wnPasswordPolicy() de app.js.
REQUIREMENTS: list[tuple[str, str, object]] = [
    ("length", f"Al menos {MIN_LENGTH} caracteres",   lambda p: len(p) >= MIN_LENGTH),
    ("upper",  "Una letra mayúscula",                  lambda p: bool(re.search(r"[A-Z]", p))),
    ("lower",  "Una letra minúscula",                  lambda p: bool(re.search(r"[a-z]", p))),
    ("digit",  "Un número",                            lambda p: bool(re.search(r"\d", p))),
    ("symbol", "Un símbolo (!@#$%^&*…)",               lambda p: bool(re.search(r"[^A-Za-z0-9]", p))),
]


def password_errors(password: str) -> list[str]:
    """Devuelve la lista de etiquetas de requisitos NO cumplidos.

    Lista vacía → contraseña válida.
    """
    return [label for _id, label, test in REQUIREMENTS if not test(password)]


def is_valid_password(password: str) -> bool:
    """True si la contraseña cumple todos los requisitos de la política."""
    return not password_errors(password)
