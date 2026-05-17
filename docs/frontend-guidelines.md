# Frontend Guidelines

## Stack frontend

- Jinja2 para renderizado server-side
- HTMX para interacción parcial
- Bootstrap para layout y componentes
- Alpine.js solo para microinteracciones locales

## Reglas

- No poner lógica de negocio en templates.
- Usar partials para respuestas HTMX.
- Usar macros Jinja2 para componentes repetidos.
- Toda acción mutante vía HTMX debe incluir CSRF.
- Alpine.js no debe manejar permisos, cálculos críticos ni estado persistente.