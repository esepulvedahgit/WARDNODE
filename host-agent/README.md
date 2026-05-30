# WardNode WF/CS — Agente del host

Este directorio contiene el agente que permite a la consola administrar recursos del host sin ejecutar comandos privilegiados directamente dentro de Flask.

El contenedor `console` se comunica con el daemon `wardnode-wf-agent.py` mediante un socket Unix montado desde el host:

```text
/app/sockets/wardnode-wf.sock  ->  /run/wardnode/wardnode-wf.sock
```

## Que instala

`install.sh` debe ejecutarse como `root` en el host. Es idempotente y realiza estas tareas:

- Instala UFW si no existe.
- Crea el grupo del sistema `wardnode` con GID `1500` si no existe.
- Crea `/run/wardnode` con permisos `root:wardnode 750` y configura `tmpfiles.d`.
- Copia `wardnode-wf-agent.py` y scripts helper a `/opt/wardnode/`.
- Instala CrowdSec y `crowdsec-firewall-bouncer-iptables` si no existen.
- Instala la coleccion `crowdsecurity/sshd`.
- Configura adquisicion de logs SSH para CrowdSec.
- Configura metricas de CrowdSec en `0.0.0.0:6060` para que Alloy pueda consultarlas desde Docker via `host.docker.internal:6060`.
- Deja CrowdSec y el bouncer desactivados hasta que el modulo CS se active desde la UI.
- Instala y arranca el servicio systemd `wardnode-wf`.

## Que no hace automaticamente

- No habilita UFW al arrancar el servicio. La inicializacion de UFW se dispara desde la UI con la accion `init_firewall`.
- No expone una shell ni acepta comandos arbitrarios. Solo procesa acciones incluidas en `ACTIONS` dentro del agente.
- No requiere sudoers para operar en la version actual: el servicio systemd corre como `root` y grupo `wardnode`.

## Acciones soportadas

WF/UFW:

- `status`
- `check_defaults`
- `init_firewall`
- `allow_port`
- `deny_port`
- `allow_ip`
- `deny_ip`
- `delete_rule`
- `get_ipv6_status`
- `set_ipv6`

CS/CrowdSec:

- `cs_status`
- `cs_decisions`
- `cs_ban`
- `cs_unban`
- `cs_start_services`
- `cs_stop_services`
- `cs_restart_services`

## Instalacion

Desde el directorio `host-agent/` en el host:

```bash
sudo bash install.sh
```

La UI tambien puede copiar e instalar estos archivos via SSH usando Paramiko cuando se configura desde el panel WF.

## Docker Compose

El contenedor `console` debe tener acceso al socket y pertenecer al grupo `wardnode` del host:

```yaml
services:
  console:
    environment:
      WF_SOCKET_PATH: /app/sockets/wardnode-wf.sock
    volumes:
      - /run/wardnode:/app/sockets:rw
    group_add:
      - "1500"
```

El socket no necesita existir antes de arrancar Docker; lo crea el servicio systemd cuando inicia el agente.

## Verificacion

```bash
systemctl status wardnode-wf
ls -la /run/wardnode/wardnode-wf.sock
```

Prueba manual del protocolo:

```bash
python3 - <<'EOF'
import json, socket

sock_path = "/run/wardnode/wardnode-wf.sock"
payload = json.dumps({"action": "status"}).encode()

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.connect(sock_path)
    s.sendall(len(payload).to_bytes(4, "big") + payload)
    rlen = int.from_bytes(s.recv(4), "big")
    print(json.loads(s.recv(rlen)))
EOF
```

## Seguridad

- Flask valida parametros antes de enviar comandos.
- El agente vuelve a validar cada campo y rechaza acciones no permitidas.
- `subprocess.run()` usa listas de argumentos y no `shell=True`.
- El socket se crea con permisos `660`; el directorio padre queda restringido a `root:wardnode`.
- El servicio corre como `root` porque UFW, systemd y CrowdSec requieren privilegios de host.
- Si el contenedor `console` se ve comprometido y tiene acceso al socket, el impacto esperado es administracion de UFW/CrowdSec dentro de las acciones permitidas, no ejecucion arbitraria de shell por el protocolo del agente.

## Archivos

- `wardnode-wf-agent.py`: daemon socket y handlers WF/CS.
- `install.sh`: instalador idempotente del agente, UFW y CrowdSec.
- `wardnode-wf.service`: unidad systemd del daemon.
- `wardnode-cs-control.sh`: wrapper allowlisted para controlar servicios CrowdSec.
- `wardnode-set-ipv6.sh`: helper para cambiar `IPV6=yes|no` en UFW y recargar.
- `sudoers-wardnode-cs`: legado/no usado por el instalador actual.
