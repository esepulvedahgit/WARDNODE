import re

CUSTOM_RULE_ID_MIN = 1_000_000
CUSTOM_RULE_ID_MAX = 1_999_999
MAX_RULE_TEXT_LENGTH = 6000
DISALLOWED_RULE_TOKENS = ("include", "exec:", "lua:")
_CTL_RE = re.compile(r"\bctl\s*:", re.IGNORECASE)
RULE_ID_RE = re.compile(r"\bid\s*:\s*'?(\d+)'?", re.IGNORECASE)

# ── Excepciones WAF por ID de regla CRS ──────────────────────────────────────
CRS_RULE_ID_MIN = 900_000
CRS_RULE_ID_MAX = 999_999

# Reglas cuya exclusión desactivaría el motor de puntuación/bloqueo del WAF.
# Nunca permitir que un operador las silencia individualmente por sitio.
CRITICAL_CRS_RULE_IDS: frozenset[int] = frozenset(
    {
        # Inicialización CRS — sin estas las variables tx.* quedan sin definir
        901001, 901100, 901120, 901130, 901140, 901150, 901160, 901170,
        901180, 901190, 901200, 901210, 901220, 901230, 901240, 901250,
        901260, 901270, 901300, 901310, 901320, 901330, 901340, 901350,
        901360, 901370, 901380, 901390, 901400, 901410, 901420,
        # Bloqueo entrante (Inbound Anomaly Score)
        949110, 949111,
        # Bloqueo saliente (Outbound Anomaly Score)
        959100,
        # Correlación / scoring final
        980130, 980140, 980170,
    }
)

MAX_EXCLUSION_COMMENT_LENGTH = 200


def validate_custom_rule(name: str, rule_text: str) -> list[str]:
    errors = []
    if not name:
        errors.append("El nombre de la regla es obligatorio.")
    if len(name) > 160:
        errors.append("El nombre de la regla excede 160 caracteres.")
    if not rule_text:
        errors.append("La regla personalizada es obligatoria.")
        return errors
    if len(rule_text) > MAX_RULE_TEXT_LENGTH:
        errors.append(f"La regla excede {MAX_RULE_TEXT_LENGTH} caracteres.")
    if "'" in rule_text:
        errors.append("Usa comillas dobles en la regla; las comillas simples no estan permitidas en este contexto.")

    lowered = rule_text.lower()
    for token in DISALLOWED_RULE_TOKENS:
        if token.lower() in lowered:
            errors.append(f"La regla contiene una accion no permitida: {token}.")
    if _CTL_RE.search(lowered):
        errors.append("La acción 'ctl:' no está permitida en reglas personalizadas.")

    statements = _statements(rule_text)
    if not statements:
        errors.append("La regla debe contener al menos una directiva SecRule o SecAction.")
        return errors

    ids = []
    for index, statement in enumerate(statements, start=1):
        if not (statement.startswith("SecRule ") or statement.startswith("SecAction ")):
            errors.append(f"Linea {index}: solo se permite SecRule o SecAction.")
        if statement.count('"') % 2 != 0:
            errors.append(f"Linea {index}: comillas dobles desbalanceadas.")
        if statement.count("'") % 2 != 0:
            errors.append(f"Linea {index}: comillas simples desbalanceadas.")
        found_id = RULE_ID_RE.search(statement)
        if found_id is None:
            errors.append(f"Linea {index}: falta accion id.")
            continue
        rule_id = int(found_id.group(1))
        ids.append(rule_id)
        if rule_id < CUSTOM_RULE_ID_MIN or rule_id > CUSTOM_RULE_ID_MAX:
            errors.append(
                f"Linea {index}: usa id {rule_id}; reserva {CUSTOM_RULE_ID_MIN}-{CUSTOM_RULE_ID_MAX}."
            )

    if len(ids) != len(set(ids)):
        errors.append("La regla contiene IDs duplicados.")

    return errors


def validate_rule_exclusion(rule_id_raw: str, comment: str) -> tuple[int | None, list[str]]:
    """Valida un ID de regla CRS para exclusión por sitio.

    Retorna (rule_id, []) si es válido, o (None, [errores]) si no lo es.

    El rule_id se interpola directamente en la directiva ``SecRuleRemoveById``
    dentro del bloque ``modsecurity_rules`` de nginx — es crítico que sea un
    entero puro sin caracteres de inyección.
    """
    errors: list[str] = []

    # ── Guard de inyección: debe ser un entero puro ───────────────────────────
    raw = (rule_id_raw or "").strip()
    if not raw:
        errors.append("El ID de regla es obligatorio.")
        return None, errors

    if not (raw.isascii() and raw.isdecimal()):
        errors.append(
            f"El ID de regla debe ser un número entero ASCII (recibido: {raw!r})."
        )
        return None, errors

    rule_id = int(raw)

    # ── Rango reservado de reglas propias ─────────────────────────────────────
    if CUSTOM_RULE_ID_MIN <= rule_id <= CUSTOM_RULE_ID_MAX:
        errors.append(
            f"El ID {rule_id} pertenece al rango de reglas personalizadas "
            f"({CUSTOM_RULE_ID_MIN}–{CUSTOM_RULE_ID_MAX}). "
            "Para desactivarla, desactívala desde el panel 'Reglas personalizadas'."
        )
        return None, errors

    # ── Rango CRS válido ──────────────────────────────────────────────────────
    if not (CRS_RULE_ID_MIN <= rule_id <= CRS_RULE_ID_MAX):
        errors.append(
            f"El ID {rule_id} no pertenece al rango de reglas CRS "
            f"({CRS_RULE_ID_MIN}–{CRS_RULE_ID_MAX})."
        )
        return None, errors

    # ── Denylist de reglas críticas ───────────────────────────────────────────
    if rule_id in CRITICAL_CRS_RULE_IDS:
        errors.append(
            f"La regla {rule_id} es crítica para el funcionamiento del WAF "
            "(scoring/bloqueo/inicialización) y no puede excluirse individualmente. "
            "Para desactivar la categoría completa usa el panel de Categorías CRS."
        )
        return None, errors

    # ── Comentario (no se renderiza a nginx, solo longitud) ───────────────────
    if len(comment) > MAX_EXCLUSION_COMMENT_LENGTH:
        errors.append(
            f"El comentario excede {MAX_EXCLUSION_COMMENT_LENGTH} caracteres."
        )
        return None, errors

    return rule_id, errors


def _statements(rule_text: str) -> list[str]:
    statements = []
    current = []
    for raw_line in rule_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        current.append(line[:-1].rstrip() if line.endswith("\\") else line)
        if not line.endswith("\\"):
            statements.append(" ".join(current).strip())
            current = []
    if current:
        statements.append(" ".join(current).strip())
    return statements
