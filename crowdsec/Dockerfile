FROM debian:bookworm-slim

# Instalar repo CrowdSec y el paquete del bouncer de nftables.
# gettext-base provee envsubst para renderizar la config template.
# Pinned a bookworm: el paquete crowdsec-firewall-bouncer-nftables
# no existe en Debian 13 Trixie (packagecloud repo no actualizado aún).
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gnupg ca-certificates gettext-base nftables \
 && curl -sSL \
    https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh \
    | bash \
 && apt-get install -y --no-install-recommends crowdsec-firewall-bouncer-nftables \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY firewall-bouncer.yaml.tpl /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.tpl
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
