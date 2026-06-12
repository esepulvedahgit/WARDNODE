#!/bin/sh
# Renderiza la config del bouncer substituyendo ${API_KEY} del entorno,
# luego arranca el bouncer en foreground.
set -e

TPL=/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.tpl
CFG=/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml

envsubst '${API_KEY}' < "${TPL}" > "${CFG}"

exec /usr/bin/crowdsec-firewall-bouncer -c "${CFG}"
