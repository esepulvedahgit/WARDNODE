# WardNode WF — Setup del host

Este directorio contiene el agente del host para el módulo **WardNode WF**.
El contenedor Flask nunca ejecuta comandos directamente; toda acción pasa por este daemon,
que valida cada request y ejecuta `ufw` con privilegios mínimos.

## ¿Qué es manual y qué es automático?

| Acción | Cuándo | Manual/Auto |
|--------|--------|-------------|
| Instalar el agente en el host | **Una sola vez** | **Manual** (SSH) |
| Arrancar el agente en reinicios | Siempre | **Automático** (systemd) |
| Habilitar UFW si está inactivo | Al arrancar el agente | **Automático** (el agente lo hace) |
| Instalar UFW si no existe | Durante `install.sh` | **Automático** |
| Aplicar reglas de firewall | Al usar el panel WF | **Automático** (via socket) |

La instalación es un **único evento manual** vía SSH. Después de eso, todo es automático.

## Instalación — un solo comando

Desde el directorio `host-agent/` del repositorio en el VPS:

```bash
sudo bash install.sh
```

El script hace todo:
- Instala UFW si no está presente
- Crea el usuario del sistema `wardnode-wf`
- Instala el agente en `/opt/wardnode/`
- Configura sudoers
- Crea `/run/wardnode` con permisos correctos (y tmpfiles.d para persistencia)
- Instala y arranca el servicio systemd
- Habilita UFW si estaba inactivo (el agente lo hace al iniciar)

## Docker Compose

El `docker-compose.vps.yml` ya incluye el bind mount necesario:

```yaml
services:
  console:
    environment:
      WF_SOCKET_PATH: /app/sockets/wardnode-wf.sock
    volumes:
      - /run/wardnode:/app/sockets:rw
```

El socket no necesita pre-existir — el agente lo crea al arrancar.

## Verificación

```bash
# El agente debe estar activo
systemctl status wardnode-wf

# El socket debe existir con permisos 660
ls -la /run/wardnode/wardnode-wf.sock

# Probar manualmente (requiere Python en el host)
python3 - <<'EOF'
import json, socket
SOCK = "/run/wardnode/wardnode-wf.sock"
payload = json.dumps({"action": "status"}).encode()
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.connect(SOCK)
    s.sendall(len(payload).to_bytes(4, "big") + payload)
    rlen = int.from_bytes(s.recv(4), "big")
    print(json.loads(s.recv(rlen)))
EOF
```

## Seguridad

- El agente valida **todos** los inputs independientemente de Flask (defensa en profundidad).
- `subprocess` usa lista de argumentos — nunca `shell=True`.
- El socket tiene permisos `660` — solo el GID `wardnode-wf` puede conectar.
- systemd hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet=` vacío.
- En caso de compromiso del contenedor Flask, el peor escenario es manipulación de reglas UFW — **no RCE en el host**.
