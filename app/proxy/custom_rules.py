import re

CUSTOM_RULE_ID_MIN = 1_000_000
CUSTOM_RULE_ID_MAX = 1_999_999
MAX_RULE_TEXT_LENGTH = 6000
DISALLOWED_RULE_TOKENS = ("include", "exec:", "lua:")
_CTL_RE = re.compile(r"\bctl\s*:", re.IGNORECASE)
RULE_ID_RE = re.compile(r"\bid\s*:\s*'?(\d+)'?", re.IGNORECASE)


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
