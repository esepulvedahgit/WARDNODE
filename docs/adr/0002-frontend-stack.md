# ADR-0002: Usar Jinja2 + HTMX + Bootstrap como stack frontend

## Estado

Aceptado.

## Fecha

2026-05-03

## Contexto

El proyecto necesita una interfaz funcional y mantenible, pero no requiere una SPA completa.
El equipo es pequeño, la lógica de negocio vive en el backend (Flask), y la prioridad es
entregar valor sin añadir complejidad accidental en el frontend.

Las principales restricciones son:

- Equipo con mayor experiencia en Python/backend que en frameworks JS modernos.
- Necesidad de renderizado server-side para simplificar autorización y control de datos.
- Evitar duplicar lógica entre cliente y servidor.
- Tiempo de entrega ajustado.

## Opciones consideradas

| Opción | Descripción |
|---|---|
| **Jinja2 + HTMX + Bootstrap** (elegida) | SSR con interacción parcial vía HTMX; sin build step; Alpine.js solo para microinteracciones locales. |
| React / Vue SPA | SPA desacoplada consumiendo una API REST o GraphQL. Mayor separación frontend/backend, pero requiere gestión de estado, build tooling y duplicación de lógica de autorización. |
| Django Templates + HTMX | Similar a la opción elegida, pero descartado por usar Flask como framework base. |
| Hotwire / Turbo (Rails-style) | Ecosistema menos maduro fuera de Rails; menor comunidad Python. |

## Decisión

Usaremos Jinja2 para renderizado server-side, HTMX para interacción parcial sin recargas
completas, Bootstrap para layout y componentes visuales, y Alpine.js exclusivamente para
microinteracciones que requieran estado local en el DOM (sin lógica de negocio).

No se usará un framework JS reactivo (React, Vue, Svelte) salvo que un módulo específico
lo justifique en un ADR separado.

## Consecuencias

### Positivas

- Menor complejidad frontend: sin build step, sin bundler, sin gestión de estado global.
- Mejor integración con Flask: autorización, CSRF y validación centralizados en el servidor.
- Menos estado en cliente: reduce superficie de ataque y errores de sincronización.
- Curva de aprendizaje baja para nuevos colaboradores con perfil backend.
- Plantillas Jinja2 son directamente testeables desde pytest.

### Negativas / Trade-offs

- Experiencias muy interactivas (drag & drop, edición en vivo, dashboards en tiempo real)
  requieren más esfuerzo o soluciones adicionales.
- HTMX tiene menor ecosistema de componentes que React/Vue.
- Alpine.js debe mantenerse acotado; su expansión no controlada puede derivar en lógica
  de negocio en el cliente, violando el principio central del proyecto.

### Riesgos

- Creep de Alpine.js: si se usa para más que microinteracciones, la arquitectura se
  degrada silenciosamente. Mitigación: revisión en code review; lógica de negocio fuera
  del cliente es regla obligatoria.
- Escalabilidad de UX: si los requisitos de interactividad crecen significativamente,
  el costo de migrar a una SPA parcial es mayor que haberlo planificado desde el inicio.

## Condiciones de reevaluación

Se revisará esta decisión si:

- Aparece un módulo con estado complejo en cliente que HTMX + Alpine.js no pueda
  manejar sin comprometer mantenibilidad.
- El equipo incorpora perfiles frontend especializados con capacidad de sostener
  un stack SPA sin aumentar deuda técnica.
- Los requisitos de UX evolucionan hacia una experiencia de aplicación nativa (offline,
  animaciones complejas, colaboración en tiempo real).

En ese caso, se creará un ADR específico para ese módulo antes de introducir nuevas
dependencias frontend.
