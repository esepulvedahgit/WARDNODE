# Stage 1: compile ngx_http_geoip2_module against the exact installed nginx version.
FROM owasp/modsecurity-crs:nginx AS builder

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       git \
       libmaxminddb-dev \
       libpcre2-dev \
       zlib1g-dev \
       wget \
    && NGINX_VERSION=$(nginx -v 2>&1 | sed 's/.*\/\([0-9.]*\).*/\1/') \
    && echo "Building geoip2 module for nginx ${NGINX_VERSION}" \
    && git clone --depth=1 https://github.com/leev/ngx_http_geoip2_module.git /tmp/geoip2 \
    && wget -qO /tmp/nginx.tar.gz "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" \
    && tar -xzf /tmp/nginx.tar.gz -C /tmp \
    && cd /tmp/nginx-${NGINX_VERSION} \
    && ./configure --with-compat --add-dynamic-module=/tmp/geoip2 \
    && make modules \
    && cp objs/ngx_http_geoip2_module.so /usr/lib/nginx/modules/

# Stage 2: final image — copy only the compiled .so, install runtime dep, patch template.
FROM owasp/modsecurity-crs:nginx

USER root

COPY --from=builder /usr/lib/nginx/modules/ngx_http_geoip2_module.so /usr/lib/nginx/modules/

# Install only the runtime library; no build tools, no autoremove risk.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libmaxminddb0 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i '1s/^/load_module modules\/ngx_http_geoip2_module.so;\n/' /etc/nginx/templates/nginx.conf.template

COPY modsecurity/modsecurity-override.conf /etc/modsecurity.d/zz-defenza-override.conf
COPY conf.d/generated.conf /etc/nginx/templates/conf.d/generated.conf.template
COPY conf.d/log-format.conf /etc/nginx/conf.d/00-log-format.conf
