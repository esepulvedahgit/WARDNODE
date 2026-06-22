"""ML embebido del SOC (Fase 5): IsolationForest sobre agregados de AttackEvent.

Detección de anomalías no supervisada como score COMPLEMENTARIO a las
heurísticas de detect.py — el heurístico es siempre el piso de severidad y el
ML solo puede subirla (services.run_detection_cycle usa max(score, ml_score)).

Entrenamiento: agregación SQL por (source_ip, bucket horario) sobre los últimos
TRAIN_LOOKBACK_DAYS — las mismas features que produce detect.find_candidates,
así el vector de scoring y el de entrenamiento son consistentes por
construcción. El modelo se serializa con joblib y se guarda en DB (SocMlModel,
LargeBinary): consistencia inmediata entre workers gunicorn y sobrevive
rebuilds del contenedor.

SEGURIDAD: joblib usa pickle. Solo se deserializan blobs escritos por
train_model() (la única ruta de escritura, sin input de usuario). JAMÁS cargar
en soc_ml_model un blob de origen externo. El training set se capa a
MAX_TRAIN_ROWS para acotar la memoria.

Degradación con gracia: si scikit-learn no está instalado, no hay modelo
entrenado o el histórico es insuficiente, score_candidate retorna None y el
SOC sigue funcionando solo con heurísticas.
"""

import io
import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, func

from app.extensions import db
from app.models import AppConfig, AttackEvent, SocMlModel

log = logging.getLogger(__name__)

MIN_TRAIN_SAMPLES = 100          # guard de arranque en frío
TRAIN_LOOKBACK_DAYS = 14
MAX_TRAIN_ROWS = 50_000          # cap del training set (DoS de memoria)
RETRAIN_INTERVAL_HOURS_DEFAULT = 24

# Orden canónico del vector de features. Si cambias esta lista, los modelos
# guardados con la lista anterior se descartan automáticamente (mismatch en
# SocMlModel.features) y se reentrenan en el siguiente maybe_retrain().
FEATURES = [
    "event_count",
    "cat_diversity",
    "path_fanout",
    "block_ratio",
    "method_diversity",
    "status_diversity",
]

# Cache módulo-level del modelo deserializado (invalidada por id de fila).
_cache: dict = {"row_id": None, "model": None, "score_min": 0.0, "score_max": 0.0}


def _cfg_int(key: str, default: int, lo: int, hi: int) -> int:
    """Lee una clave de AppConfig como int con clamp [lo, hi] y fallback al default."""
    try:
        return max(lo, min(hi, int(AppConfig.get(key) or default)))
    except (TypeError, ValueError):
        return default


def _cfg_contamination() -> "str | float":
    """Lee soc_ml_contamination desde AppConfig.

    Devuelve "auto" o un float en (0.0, 0.5]. Valor inválido → "auto".
    """
    raw = (AppConfig.get("soc_ml_contamination") or "auto").strip().lower()
    if raw == "auto":
        return "auto"
    try:
        val = float(raw)
        if 0.0 < val <= 0.5:
            return val
    except (TypeError, ValueError):
        pass
    return "auto"


def _bucket_expr():
    """Expresión SQL portable de bucket horario (PostgreSQL / SQLite)."""
    if db.engine.dialect.name == "postgresql":
        return func.date_trunc("hour", AttackEvent.created_at)
    return func.strftime("%Y-%m-%d %H", AttackEvent.created_at)


def build_training_matrix() -> list[list[float]]:
    """Matriz de features agregada por (source_ip, hora) — últimos N días."""
    since = datetime.now(timezone.utc) - timedelta(
        days=_cfg_int("soc_ml_lookback_days", TRAIN_LOOKBACK_DAYS, 1, 90)
    )
    bucket = _bucket_expr()
    rows = (
        db.session.query(
            func.count(AttackEvent.id).label("event_count"),
            func.count(func.distinct(AttackEvent.category)).label("cat_diversity"),
            func.count(func.distinct(AttackEvent.path)).label("path_fanout"),
            func.sum(case((AttackEvent.action == "block", 1), else_=0)).label("blocks"),
            func.count(func.distinct(AttackEvent.method)).label("method_diversity"),
            func.count(func.distinct(AttackEvent.status_code)).label("status_diversity"),
        )
        .filter(AttackEvent.created_at >= since)
        .group_by(AttackEvent.source_ip, bucket)
        .limit(MAX_TRAIN_ROWS)
        .all()
    )
    matrix = []
    for r in rows:
        event_count = r.event_count or 0
        block_ratio = (r.blocks or 0) / event_count if event_count else 0.0
        matrix.append([
            float(event_count),
            float(r.cat_diversity or 0),
            float(r.path_fanout or 0),
            float(block_ratio),
            float(r.method_diversity or 0),
            float(r.status_diversity or 0),
        ])
    return matrix


def train_model() -> tuple[bool, str]:
    """Entrena IsolationForest y lo persiste en SocMlModel. Nunca lanza.

    Retorna (True, "OK: N muestras") o (False, motivo).
    """
    try:
        from sklearn.ensemble import IsolationForest
        import joblib
    except ImportError:
        return False, "scikit-learn no instalado"

    try:
        matrix = build_training_matrix()
        min_samples = _cfg_int("soc_ml_min_samples", MIN_TRAIN_SAMPLES, 10, 10_000)
        if len(matrix) < min_samples:
            return False, (
                f"histórico insuficiente ({len(matrix)}/{min_samples} muestras)"
            )

        model = IsolationForest(
            n_estimators=_cfg_int("soc_ml_n_estimators", 100, 50, 500),
            contamination=_cfg_contamination(),
            random_state=42,
        )
        model.fit(matrix)

        # Calibración: rango de decision_function sobre el training set para
        # mapear el score a 0–100 (más anómalo → más alto).
        decisions = model.decision_function(matrix)
        score_min, score_max = float(decisions.min()), float(decisions.max())
        if score_max <= score_min:  # dataset degenerado (todo idéntico)
            score_max = score_min + 1e-6

        buf = io.BytesIO()
        joblib.dump(model, buf)

        # Solo se conserva la última fila.
        SocMlModel.query.delete()
        db.session.add(SocMlModel(
            blob=buf.getvalue(),
            n_samples=len(matrix),
            features=json.dumps(FEATURES),
            score_min=score_min,
            score_max=score_max,
            trained_at=datetime.now(timezone.utc),
        ))
        db.session.commit()
        _cache["row_id"] = None  # invalidar cache → recarga en próximo scoring
        log.info("soc/ml: modelo entrenado con %d muestras", len(matrix))
        return True, f"OK: {len(matrix)} muestras"
    except Exception as exc:
        db.session.rollback()
        log.warning("soc/ml: entrenamiento falló: %s", type(exc).__name__)
        return False, f"entrenamiento falló ({type(exc).__name__})"


def load_model():
    """Carga el modelo desde DB con cache. Retorna None si no hay modelo válido."""
    try:
        import joblib
    except ImportError:
        return None

    row = SocMlModel.query.order_by(SocMlModel.id.desc()).first()
    if row is None:
        return None
    # Mismatch de features → modelo obsoleto: descartar (se reentrena luego).
    try:
        if json.loads(row.features) != FEATURES:
            log.info("soc/ml: features del modelo guardado no coinciden — descartado")
            return None
    except (json.JSONDecodeError, TypeError):
        return None

    if _cache["row_id"] == row.id and _cache["model"] is not None:
        return _cache["model"]
    try:
        model = joblib.load(io.BytesIO(row.blob))
    except Exception as exc:
        log.warning("soc/ml: deserialización falló: %s", type(exc).__name__)
        return None
    _cache.update(
        row_id=row.id, model=model,
        score_min=row.score_min, score_max=row.score_max,
    )
    return model


def score_candidate(cand: dict) -> float | None:
    """Score de anomalía 0–100 para un candidato de detect.find_candidates.

    None si no hay modelo (sin sklearn, sin entrenamiento o features obsoletas).
    """
    model = load_model()
    if model is None:
        return None
    event_count = cand.get("event_count") or 0
    block_ratio = (cand.get("blocks") or 0) / event_count if event_count else 0.0
    vector = [[
        float(event_count),
        float(cand.get("cat_diversity") or 0),
        float(cand.get("path_fanout") or 0),
        float(block_ratio),
        float(cand.get("method_diversity") or 0),
        float(cand.get("status_diversity") or 0),
    ]]
    try:
        decision = float(model.decision_function(vector)[0])
    except Exception as exc:
        log.warning("soc/ml: scoring falló: %s", type(exc).__name__)
        return None
    score_min, score_max = _cache["score_min"], _cache["score_max"]
    span = score_max - score_min
    if span <= 0:
        return None
    # decision_function: más negativo = más anómalo → invertir y normalizar.
    score = 100.0 * (score_max - decision) / span
    return round(max(0.0, min(100.0, score)), 1)


def maybe_retrain() -> None:
    """Reentrena si soc_ml_enabled y el último entrenamiento está vencido.

    Llamada desde worker._run_cycle_locked DENTRO del advisory lock → solo un
    worker gunicorn entrena a la vez. Nunca lanza.
    """
    try:
        if AppConfig.get("soc_ml_enabled") != "1":
            return
        try:
            interval_h = int(
                AppConfig.get("soc_ml_retrain_hours") or RETRAIN_INTERVAL_HOURS_DEFAULT
            )
        except (TypeError, ValueError):
            interval_h = RETRAIN_INTERVAL_HOURS_DEFAULT
        interval_h = max(1, min(168, interval_h))

        last_raw = AppConfig.get("soc_ml_last_trained") or ""
        if last_raw:
            try:
                last = datetime.fromisoformat(last_raw)
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                if last >= datetime.now(timezone.utc) - timedelta(hours=interval_h):
                    return  # entrenamiento vigente
            except ValueError:
                pass  # timestamp corrupto → reentrenar

        ok, msg = train_model()
        # Registrar el intento aunque falle (histórico insuficiente) para no
        # martillear la DB en cada ciclo del worker.
        AppConfig.set("soc_ml_last_trained", datetime.now(timezone.utc).isoformat())
        if ok:
            from app.audit.helpers import log_audit

            row = SocMlModel.query.order_by(SocMlModel.id.desc()).first()
            log_audit(
                "soc.ml.trained",
                resource_type="soc_config",
                detail={"n_samples": row.n_samples if row else 0},
            )
        else:
            log.info("soc/ml: reentrenamiento omitido: %s", msg)
    except Exception as exc:
        log.warning("soc/ml: maybe_retrain falló: %s", type(exc).__name__)
        try:
            db.session.rollback()
        except Exception:
            pass
