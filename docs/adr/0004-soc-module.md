# ADR-0004: Módulo SOC embebido (detección, LLM, alertas y ML)

## Estado

Aceptado.

## Fecha

2026-06-09

## Contexto

WardNode ya ingesta eventos ModSecurity (`AttackEvent`) desde el proxy, pero el
operador debía interpretarlos a mano. Se necesitaba convertir ese flujo en
incidentes accionables (correlación, contexto de threat intel, explicación y
recomendaciones) sin añadir contenedores ni servicios externos obligatorios.

## Decisión

Se implementa el módulo SOC como blueprint embebido en la consola
(`app/soc/`), gated por `module_soc_enabled` y rol `admin`, con estas
decisiones de diseño:

### 1. El LLM analiza solo incidentes agregados, nunca eventos individuales

Llamar a un LLM por evento es inviable en costo y latencia. El pipeline es:
heurísticas SQL deterministas → incidente → enriquecimiento → LLM (con tope
`MAX_LLM_ANALYSES_PER_CYCLE`). El LLM es la última etapa, no la primera.

### 2. Capa LLM multi-proveedor vía httpx puro, sin SDKs

OpenRouter, Anthropic, OpenAI, DeepSeek y Gemini comparten un contrato común
(`LLMProvider.chat`) con timeout, tope de respuesta de 2 MB (streaming) y
errores que jamás incluyen la API key. Las keys se cifran con Fernet en
`AppConfig`. El envío de datos requiere opt-in explícito y solo incluye
metadatos agregados (jamás bodies). La salida se normaliza con un parser
tolerante que nunca lanza.

### 3. Heurísticas como piso de severidad; el ML solo puede subirla

El score heurístico (volumen, diversidad, fan-out, ratio de bloqueo) es
determinista y auditable. El IsolationForest aporta un `ml_score`
complementario: la severidad se calcula con `max(score, ml_score)`. Un modelo
mal entrenado nunca puede degradar la detección por debajo de las heurísticas.

### 4. Modelo ML serializado en base de datos, no en disco

`SocMlModel` guarda el blob joblib en PostgreSQL: consistencia inmediata entre
workers gunicorn y supervivencia a rebuilds del contenedor. Riesgo aceptado:
joblib usa pickle — mitigado porque la única ruta de escritura es
`train_model()` (sin input de usuario) y jamás se cargan blobs externos.

### 5. Un solo proceso ejecuta detección, reentrenamiento y sync CTI

Advisory lock de PostgreSQL (`pg_try_advisory_lock`, clave 815001) en el
worker. El reentrenamiento ML y el ciclo de detección corren bajo el mismo
lock; en SQLite (dev single-process) se ejecuta directo.

### 6. Base CTI MITRE local como referencia autorizada

`mitre_attack_technique` se sincroniza desde el `enterprise-attack.json`
oficial (URL fija — sin SSRF; tope 100 MB; deprecated/revoked filtradas; IDs
validados por regex). Usos: nombres/tácticas autorizados en el mapeo
CRS→MITRE, descarte de IDs alucinados por el LLM y contexto técnico en el
prompt.

### 7. Alertas con minimización de datos y cooldown

Email (SMTP global existente) y Telegram (token cifrado, chat_id validado por
regex, token jamás en logs/audit). Umbral de severidad + cooldown por IP
(`alerted_at`) contra spam. El contenido es solo metadatos del incidente —
nunca paths de ataque ni payloads, porque el canal puede viajar en claro.

## Alternativas descartadas

- **Microservicio SOC dedicado**: más superficie operativa sin beneficio a
  esta escala.
- **Dashboard Grafana para incidentes**: requeriría exponer credenciales
  PostgreSQL al stack OBS; la consola ya provee el dashboard.
- **Scoring estadístico ligero en vez de sklearn**: se eligió IsolationForest
  (plan original) aceptando ~200 MB extra de imagen.
- **SDKs oficiales de cada proveedor LLM**: httpx puro reduce dependencias y
  unifica el control de timeouts/tamaño/errores.

## Consecuencias

- `scikit-learn` entra a `requirements.txt` (~200 MB en la imagen).
- Dos migraciones nuevas (`0018`, `0019`) e índice compuesto
  `attack_event(source_ip, created_at)` para las agregaciones.
- `AttackEvent` necesita una política de retención futura (deuda conocida).
- Cobertura en `tests/test_soc.py` (detección, schema, LLM, config, MITRE,
  alertas, ML) sin servicios externos: todo mockeado salvo sklearn.
