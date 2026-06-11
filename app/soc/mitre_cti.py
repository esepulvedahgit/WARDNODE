"""Base de conocimiento MITRE ATT&CK Enterprise sincronizada desde el CTI oficial.

Descarga enterprise-attack.json (~50 MB), extrae las técnicas activas (id, name,
tácticas) y las persiste en mitre_attack_technique. Los datos sirven como
referencia autorizada para:

1. enrich.map_mitre — nombres/tácticas actualizados en el mapeo CRS→MITRE.
2. schema._coerce_mitre — validar IDs sugeridos por el LLM (anti-alucinación).
3. services._build_user_prompt — contexto técnico autorizado en el prompt LLM.

SEGURIDAD: la URL de descarga es fija (sin SSRF), la respuesta se corta a
_MAX_CTI_BYTES (patrón M-1), los technique_id se validan contra regex antes de
insertar y las técnicas deprecated/revoked se filtran. sync nunca lanza.
"""

import json
import logging
import re
from datetime import datetime, timedelta, timezone

from app.extensions import db
from app.models import MitreAttackTechnique

log = logging.getLogger(__name__)

_CTI_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
_MAX_CTI_BYTES = 100 * 1024 * 1024  # 100 MB — el archivo pesa ~50 MB hoy
_STALE_DAYS = 7
_BATCH_SIZE = 50

# Mismo formato que schema._MITRE_ID_RE — única forma válida de ID de técnica.
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def is_table_empty() -> bool:
    """True si no hay ninguna técnica sincronizada."""
    return MitreAttackTechnique.query.first() is None


def lookup_technique(technique_id: str) -> dict | None:
    """Busca una técnica en DB local. Retorna {id, name, tactic} o None."""
    if not technique_id:
        return None
    row = MitreAttackTechnique.query.filter_by(technique_id=technique_id).first()
    if row is None:
        return None
    return {"id": row.technique_id, "name": row.name, "tactic": row.tactic or ""}


def get_technique_name(technique_id: str, fallback: str = "") -> str:
    """Nombre autorizado desde DB; si no existe la fila, devuelve fallback."""
    row = lookup_technique(technique_id)
    return row["name"] if row else fallback


def get_techniques_context(technique_ids: list[str]) -> list[dict]:
    """Detalles [{id, name, tactic}] para el prompt LLM. Vacío si DB sin datos."""
    if not technique_ids:
        return []
    rows = MitreAttackTechnique.query.filter(
        MitreAttackTechnique.technique_id.in_(technique_ids)
    ).all()
    return [
        {"id": r.technique_id, "name": r.name, "tactic": r.tactic or ""} for r in rows
    ]


def _is_fresh() -> bool:
    """True si la última sync tiene menos de _STALE_DAYS días."""
    row = (
        MitreAttackTechnique.query.order_by(MitreAttackTechnique.synced_at.desc())
        .first()
    )
    if row is None:
        return False
    synced = row.synced_at
    if synced.tzinfo is None:
        synced = synced.replace(tzinfo=timezone.utc)
    return synced >= datetime.now(timezone.utc) - timedelta(days=_STALE_DAYS)


def _extract_technique(obj: dict) -> dict | None:
    """Extrae {technique_id, name, tactic, is_subtechnique} de un attack-pattern.

    Retorna None si el objeto está deprecated/revoked o no tiene un external_id
    válido de mitre-attack.
    """
    if obj.get("x_mitre_deprecated") or obj.get("revoked"):
        return None
    technique_id = None
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack":
            technique_id = ref.get("external_id")
            break
    # Validación estricta antes de insertar (mismo formato que schema.py).
    if not isinstance(technique_id, str) or not _TECHNIQUE_ID_RE.match(technique_id):
        return None
    name = obj.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    tactics = ",".join(
        kc.get("phase_name", "")
        for kc in (obj.get("kill_chain_phases") or [])
        if isinstance(kc, dict) and kc.get("phase_name")
    )
    return {
        "technique_id": technique_id,
        "name": name.strip()[:255],
        "tactic": tactics[:255],
        "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
    }


def _download_cti() -> dict:
    """Descarga el JSON CTI con cap de tamaño (patrón M-1). Lanza ante fallo."""
    import httpx

    with httpx.stream(
        "GET", _CTI_URL, timeout=httpx.Timeout(120.0, connect=10.0),
        follow_redirects=True,
    ) as resp:
        resp.raise_for_status()
        total, chunks = 0, []
        for chunk in resp.iter_bytes():
            total += len(chunk)
            if total > _MAX_CTI_BYTES:
                raise ValueError("CTI excede tamaño máximo")
            chunks.append(chunk)
    return json.loads(b"".join(chunks))


def sync_mitre_attack(force: bool = False) -> tuple[int, str]:
    """Descarga y upserta técnicas ATT&CK Enterprise. Nunca lanza.

    Retorna (n_upserted, "OK") en éxito, (0, "datos actualizados") si la sync
    es reciente y no se fuerza, o (0, mensaje_error) ante fallo.
    """
    if not force and _is_fresh():
        return 0, "datos actualizados"

    try:
        data = _download_cti()
    except Exception as exc:
        log.warning("soc/mitre: descarga CTI falló: %s", type(exc).__name__)
        return 0, f"descarga falló ({type(exc).__name__})"

    objects = data.get("objects")
    if not isinstance(objects, list):
        return 0, "estructura CTI inesperada"

    now = datetime.now(timezone.utc)
    n_upserted = 0
    try:
        for obj in objects:
            if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
                continue
            extracted = _extract_technique(obj)
            if extracted is None:
                continue
            # Upsert query+update (patrón ThreatIntelCache en enrich.py).
            row = MitreAttackTechnique.query.filter_by(
                technique_id=extracted["technique_id"]
            ).first()
            if row is None:
                row = MitreAttackTechnique(technique_id=extracted["technique_id"],
                                           name=extracted["name"], synced_at=now)
                db.session.add(row)
            row.name = extracted["name"]
            row.tactic = extracted["tactic"]
            row.is_subtechnique = extracted["is_subtechnique"]
            row.synced_at = now
            n_upserted += 1
            if n_upserted % _BATCH_SIZE == 0:
                db.session.commit()
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        log.warning("soc/mitre: upsert falló: %s", type(exc).__name__)
        return 0, f"persistencia falló ({type(exc).__name__})"

    log.info("soc/mitre: %d técnicas sincronizadas", n_upserted)
    return n_upserted, "OK"
