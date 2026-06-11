# WardNode SOC — Flujo de funcionamiento y lógica de decisiones

> Guía operativa del módulo SOC: qué hace, **por qué se dispara un incidente**,
> cómo decide la severidad, cuándo interviene la IA y cuándo se envía una alerta.
>
> Referencias técnicas complementarias: `docs/architecture.md` (sección SOC) y
> `docs/adr/0004-soc-module.md` (decisiones de diseño).

---

## 1. Visión general

El módulo SOC convierte el flujo crudo de eventos del WAF (`AttackEvent`) en
**incidentes accionables**: agrupa la actividad de cada IP atacante, la puntúa,
la enriquece con threat intel, la explica con un LLM y notifica al operador.

```
Tráfico atacante
      │
      ▼
┌─────────────┐  logs JSON   ┌──────────────────┐
│ Proxy Nginx │ ───────────► │ Ingest thread    │ ──► AttackEvent (DB)
│ ModSecurity │   (stdout)   │ (modsec-ingest)  │
└─────────────┘              └──────────────────┘
                                                       cada N minutos
┌─────────────────────────────────────────────────────────────────────┐
│ soc-worker (thread daemon + advisory lock PostgreSQL)               │
│                                                                     │
│  1. DETECCIÓN heurística (SQL agregado por IP)                      │
│  2. Scoring ML (IsolationForest, opcional)                          │
│  3. ENRIQUECIMIENTO (AbuseIPDB + MITRE ATT&CK)                      │
│  4. Creación/actualización del INCIDENTE (dedupe)                   │
│  5. ANÁLISIS LLM (opt-in, solo incidentes elegibles)                │
│  6. ALERTAS (email / Telegram, opt-in)                              │
│  7. Reentrenamiento ML (time-gated)                                 │
└─────────────────────────────────────────────────────────────────────┘
      │
      ▼
UI /soc/  →  dashboard · bitácora · detalle · campana  →  revisión humana
```

Principio rector: **cada etapa degrada con gracia**. Sin API keys → solo
heurísticas. Sin SMTP/Telegram → sin alertas pero con incidentes. Sin
histórico → sin ML. La detección nunca se detiene.

---

## 2. ¿Por qué se dispara un incidente?

Esta es la decisión central del módulo. Código: `app/soc/detect.py`.

### 2.1 La condición de entrada (filtro duro)

```
≥ 20 eventos WAF de la MISMA IP dentro de los últimos 15 minutos
```

Es la **única** condición que convierte una IP en candidata a incidente.
Detalles importantes:

- Solo cuentan eventos que **ModSecurity ya marcó** (bloqueos o detecciones
  según el modo del sitio). El tráfico legítimo jamás entra en este conteo.
- La agregación es una sola query SQL:
  `GROUP BY source_ip … HAVING count(*) >= umbral`.
- Se agrupa **solo por IP origen**: un atacante que barre varios dominios
  protegidos es UN único incidente (el dominio dominante queda como referencia).
- Las IPs no parseables se descartan (basura atacante-controlada en headers).
- Las IPs **privadas sí se aceptan**: un atacante interno es un incidente válido.

| Parámetro | Clave AppConfig | Default |
|---|---|---|
| Ventana de correlación | `soc_window_minutes` | 15 min |
| Mínimo de eventos | `soc_threshold_events` | 20 |

> ⚠️ **Limitación conocida (criterio volumétrico)**: 19 eventos en 15 minutos
> = ningún incidente, aunque los payloads sean graves. Un atacante
> *low-and-slow* (1 request por hora) no genera incidente hoy. Los eventos
> sueltos siguen visibles en `/proxy/events`.

### 2.2 El score heurístico (decide la severidad, no la existencia)

Superado el umbral, el incidente **se crea siempre**. El score 0–100 solo
gradúa su gravedad. Fórmula (`detect.score_candidate`):

```
score = volumen       (0–40)  =  40 × eventos / (2 × umbral)
      + diversidad    (0–20)  =  5 × nº de categorías CRS distintas
      + ratio bloqueo (0–20)  =  20 × (eventos bloqueados / total)
      + fan-out       (0–20)  =  2 × nº de paths distintos
```

Interpretación de cada componente:

| Componente | Pregunta que responde |
|---|---|
| Volumen | ¿Cuánto martilla? (satura a 40 con 2× el umbral) |
| Diversidad | ¿Prueba varias clases de ataque (SQLi + XSS + LFI…)? |
| Ratio de bloqueo | ¿El WAF lo está frenando activamente? |
| Fan-out | ¿Escanea muchas rutas distintas (recon/scanner)? |

Mapeo score → severidad (`detect.severity_for_score`):

| Score | Severidad |
|---|---|
| ≥ 80 | `critical` |
| ≥ 60 | `high` |
| ≥ 40 | `medium` |
| < 40 | `low` |

### 2.3 Los tres modificadores posteriores

Aplicados en `app/soc/services.py:run_detection_cycle`, en este orden:

1. **Score ML** (si `soc_ml_enabled == "1"` y hay modelo entrenado):
   el IsolationForest puntúa la anomalía del mismo vector de features y la
   severidad se calcula sobre `max(score_heurístico, ml_score)`.
   **El ML solo puede SUBIR la severidad, nunca bajarla** — el heurístico es
   siempre el piso.

2. **Reputación AbuseIPDB**: si `abuseConfidenceScore ≥ 75`, la severidad
   **sube un nivel** (ej. high → critical, con tope en critical).

3. **Dedupe (anti-duplicados)**: si ya existe un incidente en estado `nuevo`
   de la misma IP con `window_end` dentro de la última hora, **no se crea otro**:
   se actualiza el existente (ventana extendida; eventos, score, ml_score y
   severidad solo al alza).

### 2.4 Ejemplos concretos

**✅ Genera incidente — atacante activo:**

Una IP lanza 50 requests SQLi + XSS contra 30 paths en 10 minutos, todo bloqueado:

```
volumen   = min(40, 40 × 50/40)   = 40
diversidad = min(20, 5 × 2)       = 10
bloqueo   = 20 × (50/50)          = 20
fan-out   = min(20, 2 × 30)       = 20
                            score = 90 → critical
```

Pasa el umbral (50 ≥ 20) → incidente `critical`. Si además AbuseIPDB la conoce,
sigue critical (ya es tope). Con alertas activas → email/Telegram.

**❌ NO genera incidente:**

- 19 eventos en 15 minutos (no alcanza el umbral).
- 5 requests RCE aislados (graves, pero volumétricamente insuficientes).
- 1 request por hora durante un día (*low-and-slow*: nunca hay 20 en una ventana).

**🔁 NO genera un SEGUNDO incidente:**

- La misma IP sigue atacando 20 minutos después de creado su incidente:
  el dedupe actualiza el incidente abierto (más eventos, score al alza),
  no crea uno nuevo ni dispara otra alerta.

---

## 3. El ciclo del worker

Código: `app/soc/worker.py`. Thread daemon `soc-worker` que arranca con la app.

| Aspecto | Valor |
|---|---|
| Tick del loop | cada 15 s (comprueba si toca trabajar) |
| Intervalo real del ciclo | `soc_worker_interval_min` (default 5 min, rango 1–60) |
| Delay tras boot | 60 s |
| Backoff tras error | 30 s |

- **Módulo apagado** (`module_soc_enabled != "1"`): el thread queda ocioso
  (loop sin trabajo, costo ~0). Se puede activar sin reiniciar.
- **Multi-worker (gunicorn + PostgreSQL)**: un *advisory lock*
  (`pg_try_advisory_lock`, clave 815001) garantiza que **solo un proceso**
  ejecute el ciclo y el reentrenamiento ML. En SQLite (dev) se ejecuta directo.
- **Primera ejecución**: si la tabla MITRE local está vacía, descarga el CTI
  oficial una única vez por proceso.
- Consecuencia práctica: el SOC **no es tiempo real puro** — un ataque se
  convierte en incidente como máximo ~`intervalo` minutos después (default ≤5 min).

---

## 4. Enriquecimiento del incidente

Código: `app/soc/enrich.py` y `app/soc/mitre_cti.py`. Nunca bloquea la creación
del incidente: cualquier fallo degrada con gracia.

### 4.1 AbuseIPDB (reputación de la IP)

| Control | Valor |
|---|---|
| Solo IPs **públicas** | privadas/loopback/reservadas → no se consulta (no se envían datos atacante-controlados a terceros) |
| Cache local (`ThreatIntelCache`) | TTL 24 h (`soc_abuse_cache_ttl_hours`) — IPs repetidas no consumen cuota |
| Tope por ciclo | 25 llamadas (`MAX_ENRICH_PER_CYCLE`) — protege la cuota free (1.000/día) |
| Tope de respuesta | 256 KB |
| Efecto | `abuse_score` en el incidente; ≥75 sube la severidad un nivel |

### 4.2 MITRE ATT&CK

- Mapeo estático `categoría CRS → técnicas` (ej. `sql-injection → T1190`,
  `scanner → T1595/T1046`, `brute-force → T1110`).
- Si la **base CTI local** está sincronizada (botón en `/soc/config` o sync
  automática inicial), los **nombres y tácticas** se toman de ahí (referencia
  autorizada, ~650 técnicas Enterprise del `enterprise-attack.json` oficial).
- La misma base **valida los IDs que sugiere el LLM**: un ID con formato válido
  pero inexistente en ATT&CK real se descarta (anti-alucinación).

---

## 5. Análisis con IA (LLM)

Código: `app/soc/services.py:analyze_incident` + `app/soc/llm/`.

### 5.1 Los 4 guards (todos deben cumplirse)

```
1. Opt-in de datos       soc_data_optin == "1"   (checkbox explícito; default OFF)
2. Severidad ≥ umbral    soc_analyze_min_severity (default "medium")
3. Proveedor disponible  alguna API key configurada (con fallback automático)
4. Sin análisis previo   un incidente se analiza UNA sola vez
```

Además: máximo **5 análisis por ciclo** (`MAX_LLM_ANALYSES_PER_CYCLE`),
priorizando los de mayor severidad — control de costos.

### 5.2 Qué se envía (minimización de datos)

Solo metadatos agregados: IP, dominio, ventana, conteos, categorías CRS,
reglas disparadas, top de paths **truncados a 120 chars**, scores y el contexto
MITRE autorizado. **Nunca** bodies de peticiones ni mensajes completos de
ModSecurity. Los valores atacante-controlados pasan por neutralización de
saltos de línea (defensa anti prompt-injection) y el system prompt instruye al
modelo a tratar todo el bloque de datos como evidencia, jamás como instrucciones.

### 5.3 Proveedores y fallback

| Proveedor | Modelo default |
|---|---|
| OpenRouter | `anthropic/claude-sonnet-4.5` |
| Anthropic | `claude-sonnet-4-5` |
| OpenAI | `gpt-4o-mini` |
| DeepSeek | `deepseek-chat` |
| Gemini | `gemini-2.0-flash` |

Si el proveedor activo no tiene key, se recorre el orden
`openrouter → anthropic → openai → deepseek → gemini` y se usa el primero con
key. Sin keys → el SOC funciona solo con heurísticas.

La salida del LLM (summary, hipótesis con confianza, recomendaciones
priorizadas, técnicas MITRE, IoCs) pasa por un normalizador **tolerante que
nunca lanza**: enums inválidos se corrigen, listas se capan, IDs MITRE
alucinados se descartan contra la base CTI.

---

## 6. Sistema de alertas

Código: `app/soc/alerts.py`. **Apagado por defecto** (opt-in).

### 6.1 La cadena de 7 condiciones (todas deben cumplirse)

```
1. Módulo SOC activo        module_soc_enabled == "1"
2. Worker corriendo          (siempre vivo, pero ocioso si el módulo está off)
3. Alertas habilitadas       soc_alerts_enabled == "1"      ← DEFAULT: OFF
4. Incidente NUEVO creado    solo al crearse (no por dedupe ni incidentes viejos)
5. Severidad ≥ umbral        soc_alert_min_severity (default "high")
6. Fuera del cooldown        sin otra alerta de la MISMA IP en
                             soc_alert_cooldown_min (default 60 min, rango 5–1440)
7. Canal configurado         email: SMTP global + destinos válidos
                             telegram: bot token (cifrado) + chat_id válido
```

### 6.2 Comportamiento

- **Anti-spam por diseño**: dedupe (1 incidente/IP/hora) + cooldown
  (1 alerta/IP/cooldown) → un atacante persistente no inunda la bandeja.
- **Best-effort por canal**: si SMTP falla pero Telegram funciona, llega la de
  Telegram. Si ambos fallan → `soc.alert.failed` en auditoría y el ciclo sigue.
- **Contenido mínimo**: id, severidad, IP, dominio, conteos, scores, summary IA
  (si existe) y link al detalle. **Nunca paths de ataque ni payloads** — el
  canal puede viajar en claro.
- **Secretos**: el bot token se guarda cifrado (Fernet) y jamás aparece en
  logs, errores ni auditoría.
- La alerta se evalúa **después** del análisis LLM del ciclo, para poder
  incluir el summary de la IA.

---

## 7. Scoring ML (IsolationForest)

Código: `app/soc/ml.py`. **Opt-in** (`soc_ml_enabled`, default OFF).

| Aspecto | Valor |
|---|---|
| Algoritmo | IsolationForest (scikit-learn), `contamination="auto"` |
| Features (6) | `event_count`, `cat_diversity`, `path_fanout`, `block_ratio`, `method_diversity`, `status_diversity` |
| Datos de entrenamiento | agregados por (IP, hora) de los últimos 14 días |
| Mínimo para entrenar | 100 muestras (arranque en frío: sin histórico no hay ML) |
| Tope del training set | 50.000 filas |
| Reentrenamiento | cada `soc_ml_retrain_hours` (default 24 h) dentro del advisory lock, o manual con "Entrenar ahora" |
| Persistencia | blob joblib en DB (`soc_ml_model`) — consistente entre workers, sobrevive rebuilds |

Reglas clave:

- **El heurístico es siempre el piso**: `severidad = f(max(score, ml_score))`.
  Un modelo mal entrenado no puede degradar la detección.
- El score 0–100 se calibra con el rango de `decision_function` del training
  set (más anómalo → más alto).
- Si las features del modelo guardado no coinciden con las actuales del código,
  el modelo se descarta y se reentrena solo.
- Seguridad: jamás cargar blobs externos en `soc_ml_model` (joblib = pickle);
  la única ruta de escritura es el propio entrenamiento.

---

## 8. Estados del incidente y revisión humana

```
            ┌──────────┐
   creación │  nuevo   │ ← cuenta en la campana 🔔
            └────┬─────┘
   operador      │
   decide:       ▼
   ┌────────────┬─────────────┬──────────────┐
   │ confirmado │  revisado   │  descartado  │
   │ (ataque    │ (visto, sin │ (falso       │
   │  real)     │  acción)    │  positivo)   │
   └────────────┴─────────────┴──────────────┘
```

- La **campana** del topbar muestra el conteo de incidentes `nuevo`
  (endpoint `/soc/notifications/count`, refresco periódico).
- Cambiar el estado registra quién y cuándo (`reviewed_by`, `reviewed_at`) y
  queda en auditoría. Volver a `nuevo` limpia la revisión.
- Un incidente `descartado`/`revisado` **sale del dedupe**: si la IP vuelve a
  atacar, se crea un incidente nuevo (y puede volver a alertar pasado el cooldown).
- **Bitácora** (`/soc/bitacora`): filtros por estado/severidad/fechas,
  paginación y export CSV (máx. 10.000 filas).

---

## 9. Garantías transversales

| Garantía | Implementación |
|---|---|
| Degradación con gracia | cada etapa es best-effort; la detección heurística nunca depende de servicios externos |
| Secretos cifrados | API keys LLM, AbuseIPDB y bot Telegram con Fernet (`WARDNODE_SECRET_KEY`); enmascarados en UI; jamás en logs/audit |
| Caps de egress | 2 MB respuesta LLM · 256 KB AbuseIPDB · 100 MB CTI MITRE (streaming con corte) |
| Anti prompt-injection | neutralización de `\n`/`\r` en valores atacante-controlados + instrucción explícita en el system prompt |
| Anti-alucinación MITRE | IDs del LLM validados por regex Y contra la base CTI local |
| RBAC | todas las rutas `/soc/*` son solo `admin` + módulo activo |
| Multi-worker seguro | advisory lock PostgreSQL para ciclo, ML y sync CTI |
| Auditoría | `soc.incident.created`, `soc.analysis.failed`, `soc.alert.sent/failed`, `soc.mitre.sync`, `soc.ml.trained`, `soc.config.update` — solo nombres de campos, jamás valores secretos |

---

## 10. Referencia rápida

### 10.1 Claves AppConfig del SOC

| Clave | Efecto | Default |
|---|---|---|
| `module_soc_enabled` | activa el módulo completo | `0` |
| `soc_window_minutes` | ventana de correlación de la detección | `15` |
| `soc_threshold_events` | mínimo de eventos por IP para crear incidente | `20` |
| `soc_worker_interval_min` | cadencia del ciclo del worker (1–60) | `5` |
| `soc_data_optin` | consentimiento de envío de metadatos al LLM | `0` |
| `soc_llm_provider` | proveedor LLM activo | `openrouter` |
| `soc_llm_model` | modelo (vacío = default del proveedor) | `""` |
| `soc_analyze_min_severity` | severidad mínima para análisis IA | `medium` |
| `soc_*_api_key` (×5) + `soc_abuseipdb_api_key` | API keys (cifradas) | — |
| `soc_abuse_cache_ttl_hours` | TTL del cache de reputación | `24` |
| `soc_alerts_enabled` | activa alertas | `0` |
| `soc_alert_min_severity` | severidad mínima para alertar | `high` |
| `soc_alert_email_to` | destinos email (CSV) | `""` |
| `soc_alert_telegram_token` | bot token (cifrado) | — |
| `soc_alert_telegram_chat_id` | chat destino | `""` |
| `soc_alert_cooldown_min` | cooldown por IP (5–1440) | `60` |
| `soc_alert_base_url` | prefijo del link en alertas (opcional) | `""` |
| `soc_ml_enabled` | activa scoring ML | `0` |
| `soc_ml_retrain_hours` | cadencia de reentrenamiento (1–168) | `24` |

### 10.2 Mapa de archivos fuente

| Archivo | Responsabilidad |
|---|---|
| `app/soc/worker.py` | loop periódico, advisory lock, sync CTI inicial |
| `app/soc/detect.py` | umbral, agregación SQL, score heurístico, severidad |
| `app/soc/services.py` | orquestación del ciclo, dedupe, prompt LLM, guards |
| `app/soc/enrich.py` | AbuseIPDB + cache, mapeo CRS→MITRE |
| `app/soc/mitre_cti.py` | sync y consulta de la base CTI local |
| `app/soc/llm/` | proveedores (base/providers/router), fallback, caps |
| `app/soc/schema.py` | normalización tolerante de la salida LLM |
| `app/soc/alerts.py` | cadena de alertas, cooldown, email/Telegram |
| `app/soc/ml.py` | entrenamiento, persistencia y scoring IsolationForest |
| `app/soc/routes.py` | UI: dashboard, bitácora, detalle, config, sync/train |

### 10.3 Tuning rápido de sensibilidad

| Quiero… | Ajuste |
|---|---|
| Detectar atacantes más lentos | bajar `soc_threshold_events` (ej. 10) y/o subir `soc_window_minutes` (ej. 60) |
| Menos ruido de incidentes | subir `soc_threshold_events` |
| Incidentes más rápido | bajar `soc_worker_interval_min` (mín. 1) |
| Más/menos alertas | ajustar `soc_alert_min_severity` y `soc_alert_cooldown_min` |
| Más análisis IA | bajar `soc_analyze_min_severity` (ojo con el costo: cap 5/ciclo) |
