# Plantilla de configuración del firewall-bouncer.
# ${API_KEY} es sustituido por entrypoint.sh en tiempo de ejecución.
api_url: ${API_URL}
api_key: ${API_KEY}

mode: nftables
update_frequency: 10s
log_level: info
log_media: stdout

# Tabla nftables propia — no interfiere con reglas UFW.
# Los baneos se aplican en el namespace de red del host (network_mode: host).
nftables:
  ipv4:
    enabled: true
    set-only: false
    table: crowdsec
    chain: crowdsec-chain
  ipv6:
    enabled: true
    set-only: false
    table: crowdsec6
    chain: crowdsec-chain

prometheus:
  enabled: false
