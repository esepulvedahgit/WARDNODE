# ADR-0001: Arquitectura modular en capas con Flask SSR

## Estado

Aceptado.

## Fecha

2026-05-03

## Contexto

El proyecto es una aplicación web con lógica de negocio no trivial. Se necesita una
arquitectura que permita crecer sin convertirse en un monolito inmanejable, que sea
testeable sin levantar el servidor HTTP, y que evite que la lógica de negocio quede
dispersa en rutas, templates o JavaScript.

Las restricciones principales son:

- Equipo pequeño: la arquitectura debe ser comprensible sin documentación adicional.
- Flask como framework base: no impone estructura, por lo que la arquitectura debe
  ser explícita y acordada.
- Prioridad de mantenibilidad sobre optimización prematura.
- Necesidad de testear servicios y dominio sin dependencia del contexto HTTP.

## Opciones consideradas

| Opción | Descripción |
|---|---|
| **Capas explícitas: routes / services / domain / models** (elegida) | Separación clara de responsabilidades. Lógica de negocio en servicios y dominio; Flask solo maneja HTTP. |
| Flask sin estructura (fat routes) | Todo en blueprints y rutas. Simple al inicio, inmanejable a medida que crece. Difícil de testear. |
| Clean Architecture / Ports & Adapters estricta | Mayor aislamiento, pero excesiva para el tamaño actual del proyecto. Introduce abstracciones prematuras. |
| Microservicios | Complejidad operacional injustificada para el alcance actual. |

## Decisión

Adoptamos una arquitectura modular en capas con las siguientes responsabilidades fijas:

- **Routes / Blueprints:** reciben requests HTTP, delegan en servicios, renderizan respuesta.
  No contienen lógica de negocio.
- **Services:** coordinan casos de uso. Orquestan dominio y persistencia. Son el punto
  de entrada para tests de integración.
- **Domain:** contiene reglas de negocio, invariantes y entidades. No depende de Flask
  ni de SQLAlchemy directamente.
- **Models (SQLAlchemy):** mapeo objeto-relacional. Persisten y recuperan datos.
- **Templates (Jinja2):** renderizan únicamente; no toman decisiones de negocio.

La lógica de negocio no debe vivir en rutas, templates ni JavaScript de interfaz.

## Consecuencias

### Positivas

- Servicios y dominio son testeables sin contexto HTTP ni base de datos real (unit tests).
- Cambios en persistencia o en UI no afectan la lógica de negocio.
- Incorporación de nuevos colaboradores: la estructura es predecible.
- Facilita aplicar principios de *Architecture Patterns with Python* de forma incremental.

### Negativas / Trade-offs

- Requiere disciplina: Flask no impone la separación, el equipo debe sostenerla.
- Para funcionalidades muy simples (CRUD directo), la capa de servicios puede sentirse
  como indirección innecesaria.
- Mayor cantidad de archivos que un enfoque fat-routes.

### Riesgos

- Erosión gradual: sin revisión en code review, la lógica puede migrar a las rutas.
  Mitigación: regla explícita en CLAUDE.md y revisión de PRs.
- Sobreingeniería de dominio: no toda entidad necesita comportamiento rico. Aplicar
  solo donde las reglas de negocio lo justifiquen.

## Condiciones de reevaluación

Se revisará si:

- El proyecto escala a múltiples equipos trabajando en dominios independientes
  (considerar bounded contexts o extracción de servicios).
- La complejidad del dominio justifica adoptar Ports & Adapters de forma más estricta.
