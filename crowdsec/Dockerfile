FROM debian:bookworm-slim

# Instalar el bouncer de nftables de CrowdSec.
# gettext-base provee envsubst para renderizar la config template.
#
# PINNING DE SEGURIDAD (supply chain):
#   - Repo añadido con firma GPG verificada (signed-by) en lugar de curl | bash ciego.
#   - Versión del paquete fijada explícitamente para builds reproducibles.
#   - Base fijada a debian:bookworm-slim: crowdsec-firewall-bouncer-nftables
#     no existe en Debian 13 Trixie (packagecloud repo no actualizado aún).
#
# Para actualizar el bouncer a una versión nueva:
#   1. Ejecuta: apt-cache madison crowdsec-firewall-bouncer-nftables
#      dentro de un contenedor bookworm con el repo de CrowdSec.
#   2. Actualiza BOUNCER_VERSION al valor deseado.
#   3. Rebuild y verifica con: crowdsec-firewall-bouncer -version
ARG BOUNCER_VERSION=0.0.34

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl gnupg ca-certificates gettext-base nftables \
 && curl -fsSL https://packagecloud.io/crowdsec/crowdsec/gpgkey \
      | gpg --dearmor -o /usr/share/keyrings/crowdsec.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/crowdsec.gpg] \
https://packagecloud.io/crowdsec/crowdsec/debian bookworm main" \
      > /etc/apt/sources.list.d/crowdsec.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      "crowdsec-firewall-bouncer-nftables=${BOUNCER_VERSION}" \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 # Eliminar la config por defecto del paquete (placeholder <API_KEY>, sin secreto):
 # la config real se renderiza en /dev/shm (tmpfs) por entrypoint.sh.
 && rm -f /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml

COPY firewall-bouncer.yaml.tpl /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.tpl
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
