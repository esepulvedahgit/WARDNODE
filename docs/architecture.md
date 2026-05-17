# Arquitectura del proyecto

## Estado

Inicial / en diseño.

## Objetivo

Construir una aplicación Flask modular, mantenible y segura, preparada para crecer sin introducir sobreingeniería desde el inicio.

## Stack base

- Python
- Flask
- SQLAlchemy
- Alembic / Flask-Migrate
- Jinja2
- HTMX
- Bootstrap
- Alpine.js solo para microinteracciones
- pytest
- Docker / Docker Compose

## Estilo arquitectónico

La aplicación usará Flask como capa HTTP.

La lógica de negocio no debe vivir en rutas ni templates. Cuando exista lógica relevante, debe moverse a servicios de aplicación y, si el dominio lo justifica, a entidades/value objects del dominio.

## Capas previstas

- `app/routes` o blueprints: entrada HTTP.
- `app/services`: casos de uso.
- `app/domain`: reglas e invariantes del negocio.
- `app/models`: modelos SQLAlchemy.
- `app/repositories`: acceso a datos cuando ayude a desacoplar.
- `app/templates`: presentación Jinja2.
- `tests`: pruebas unitarias e integración.

## Decisiones pendientes

- Base de datos definitiva.
- Estrategia de autenticación.
- Modelo multiusuario o multitenant.
- Política de auditoría.
- Estrategia de despliegue.