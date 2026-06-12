#!/bin/sh
# Renderiza la config del bouncer substituyendo ${API_KEY} del entorno,
# luego arranca el bouncer en foreground.
# La config renderizada (contiene la key en claro) se escribe en /dev/shm —
# tmpfs por defecto en Docker — para que nunca persista en disco (overlay2).
set -e

TPL=/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.tpl
CFG=/dev/shm/crowdsec-firewall-bouncer.yaml

# API_URL: URL del LAPI de CrowdSec. Valor por defecto para dev (bridge: crowdsec:8080);
# en producción (network_mode: host) se sobreescribe con http://127.0.0.1:9080.
export API_URL="${API_URL:-http://127.0.0.1:8080}"
umask 077
envsubst '${API_KEY} ${API_URL}' < "${TPL}" > "${CFG}"

exec /usr/bin/crowdsec-firewall-bouncer -c "${CFG}"
