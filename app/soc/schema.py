"""Esquema estandarizado de la salida LLM del SOC.

Todo proveedor debe devolver el mismo JSON; normalize_llm_output() lo valida
y normaliza con tolerancia total: nunca lanza, siempre retorna un dict válido.
"""

import json
import re

_SEVERITIES = {"critical", "high", "medium", "low"}
_PRIORITIES = {"alta", "media", "baja"}
_ACTION_TYPES = {"bloquear_ip", "ajustar_regla", "investigar", "monitorear"}
_IOC_TYPES = {"ip", "domain", "url", "path", "user_agent", "hash"}
_MITRE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

_MAX_LIST_ITEMS = 10
_MAX_SUMMARY = 1000
_MAX_EXPLANATION = 5000
_MAX_TEXT = 1000
_MAX_IOC_VALUE = 500

EMPTY_ANALYSIS: dict = {
    "summary": "",
    "explanation": "",
    "severity_suggested": "medium",
    "confidence": 0,
    "hypotheses": [],
    "recommendations": [],
    "mitre_techniques": [],
    "iocs": [],
}


def _strip_fences(raw: str) -> str:
    """Quita fences markdown (```json ... ```) si los hay."""
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def _parse_json(raw: str) -> dict | None:
    text = _strip_fences(raw)
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, ValueError):
        pass
    # Fallback: extraer el primer bloque {...}
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            data = json.loads(text[start : end + 1])
            return data if isinstance(data, dict) else None
        except (json.JSONDecodeError, ValueError):
            pass
    return None


def _salvage_partial(raw: str) -> dict:
    """Extrae campos de un JSON truncado/malformado sin exponer llaves crudas.

    Cuando el modelo supera el límite de tokens el JSON queda incompleto y
    json.loads falla.  Esta función extrae summary y explanation por regex
    (tolerante a escapes JSON internos) y devuelve un dict parcialmente poblado,
    garantizando que summary NUNCA empiece por '{'.
    """
    text = _strip_fences(raw)
    result = dict(EMPTY_ANALYSIS)

    if not text.startswith("{"):
        # Prosa libre legítima (ej. proveedor ignoró la instrucción JSON)
        result["summary"] = text[:_MAX_SUMMARY]
        return result

    # JSON roto: extraer campos por regex sin depender de parseo completo
    _STR_VALUE_RE = r'"(?:\\.|[^"\\])*"'
    for field, max_len in (("summary", _MAX_SUMMARY), ("explanation", _MAX_EXPLANATION)):
        pattern = rf'"{field}"\s*:\s*({_STR_VALUE_RE})'
        m = re.search(pattern, text)
        if m:
            try:
                result[field] = _coerce_str(
                    _json_loads_str(m.group(1)), max_len
                )
            except Exception:
                pass  # campo queda vacío — nunca llaves crudas

    # Intentar severidad y confianza (valores simples, fáciles de extraer)
    m_sev = re.search(r'"severity_suggested"\s*:\s*"([^"]+)"', text)
    if m_sev and m_sev.group(1) in _SEVERITIES:
        result["severity_suggested"] = m_sev.group(1)

    m_conf = re.search(r'"confidence"\s*:\s*(\d+)', text)
    if m_conf:
        result["confidence"] = _coerce_confidence(m_conf.group(1))

    return result


def _json_loads_str(s: str):
    """Parsea un string JSON entre comillas, incluyendo escapes."""
    return json.loads(s)


def _coerce_str(value, max_len: int) -> str:
    if not isinstance(value, str):
        return ""
    return value[:max_len]


def _coerce_confidence(value) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 0


def _coerce_hypotheses(items) -> list[dict]:
    out = []
    if not isinstance(items, list):
        return out
    for item in items[:_MAX_LIST_ITEMS]:
        if not isinstance(item, dict):
            continue
        text = _coerce_str(item.get("text"), _MAX_TEXT)
        if text:
            out.append({"text": text, "confidence": _coerce_confidence(item.get("confidence"))})
    return out


def _coerce_recommendations(items) -> list[dict]:
    out = []
    if not isinstance(items, list):
        return out
    for item in items[:_MAX_LIST_ITEMS]:
        if not isinstance(item, dict):
            continue
        text = _coerce_str(item.get("text"), _MAX_TEXT)
        if not text:
            continue
        priority = item.get("priority")
        if priority not in _PRIORITIES:
            priority = "media"
        action_type = item.get("action_type")
        if action_type not in _ACTION_TYPES:
            action_type = "investigar"
        out.append({"text": text, "priority": priority, "action_type": action_type})
    return out


def _coerce_mitre(items) -> list[dict]:
    # SEGURIDAD (M-2): la plantilla detalle.html construye un href de la forma
    #   href="https://attack.mitre.org/techniques/{{ t.id | replace('.', '/') }}/"
    # con valores provenientes del LLM. La validación estricta aquí es la única
    # barrera que evita XSS por atributo (ej. id="javascript:..."). NO relajar
    # ni reemplazar _MITRE_ID_RE sin revisar detalle.html simultáneamente.
    #
    # Anti-alucinación: si la base CTI local (mitre_attack_technique) tiene
    # datos, los IDs que no existan en ATT&CK real se descartan y los nombres
    # se reemplazan por los autorizados del DB.
    from app.soc import mitre_cti

    try:
        db_available = not mitre_cti.is_table_empty()
    except Exception:
        db_available = False  # sin app context / tabla aún no migrada

    out = []
    if not isinstance(items, list):
        return out
    for item in items[:_MAX_LIST_ITEMS]:
        if not isinstance(item, dict):
            continue
        tid = item.get("id")
        if not isinstance(tid, str) or not _MITRE_ID_RE.match(tid):
            continue
        if db_available:
            row = mitre_cti.lookup_technique(tid)
            if row is None:
                continue  # ID con formato válido pero inexistente en ATT&CK
            out.append({"id": tid, "name": row["name"], "tactic": row["tactic"]})
        else:
            out.append({"id": tid, "name": _coerce_str(item.get("name"), _MAX_TEXT),
                        "tactic": ""})
    return out


def _coerce_iocs(items) -> list[dict]:
    out = []
    if not isinstance(items, list):
        return out
    for item in items[:_MAX_LIST_ITEMS]:
        if not isinstance(item, dict):
            continue
        ioc_type = item.get("type")
        value = _coerce_str(item.get("value"), _MAX_IOC_VALUE)
        if ioc_type in _IOC_TYPES and value:
            out.append({"type": ioc_type, "value": value})
    return out


def normalize_llm_output(raw: str) -> dict:
    """Parseo tolerante de la salida LLM. Nunca lanza; siempre dict válido."""
    if not isinstance(raw, str):
        return dict(EMPTY_ANALYSIS)

    data = _parse_json(raw)
    if data is None:
        # JSON inválido o truncado: extraer lo que se pueda sin volcar llaves crudas
        return _salvage_partial(raw)

    severity = data.get("severity_suggested")
    if severity not in _SEVERITIES:
        severity = "medium"

    return {
        "summary": _coerce_str(data.get("summary"), _MAX_SUMMARY),
        "explanation": _coerce_str(data.get("explanation"), _MAX_EXPLANATION),
        "severity_suggested": severity,
        "confidence": _coerce_confidence(data.get("confidence")),
        "hypotheses": _coerce_hypotheses(data.get("hypotheses")),
        "recommendations": _coerce_recommendations(data.get("recommendations")),
        "mitre_techniques": _coerce_mitre(data.get("mitre_techniques")),
        "iocs": _coerce_iocs(data.get("iocs")),
    }
