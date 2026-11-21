#!/bin/sh
# Validates the OPLIA_CONSOLE_* settings, writes /config.json and the nginx server block, starts nginx.
# Every value is checked against a strict pattern, so nothing can break out of JSON or nginx syntax.
set -eu

fail() { echo "oplia-console: $*" >&2; exit 1; }
NL='
'
# whole-value match: grep tests line by line, so values containing a newline are refused first
matches() { case "$1" in *"$NL"*) return 1 ;; esac; printf '%s' "$1" | grep -Eq "^$2\$"; }

AUTHORITY=${OPLIA_CONSOLE_AUTHORITY:-}
CLIENT_ID=${OPLIA_CONSOLE_CLIENT_ID:-}
SCOPE=${OPLIA_CONSOLE_SCOPE:-openid profile}
LABEL=${OPLIA_CONSOLE_ENVIRONMENT_LABEL:-}
UPSTREAM=${OPLIA_CONSOLE_API_UPSTREAM:-}
ALLOW_HTTP=${OPLIA_CONSOLE_ALLOW_HTTP_AUTHORITY:-false}
OUT=/tmp/oplia  # fixed: nginx.conf includes /tmp/oplia/server.conf
HTML=${OPLIA_CONSOLE_HTML_DIR:-/opt/oplia-console/html}

[ -n "$AUTHORITY" ] || fail "OPLIA_CONSOLE_AUTHORITY is required (issuer URL of Entra ID / Okta)"
[ -n "$CLIENT_ID" ] || fail "OPLIA_CONSOLE_CLIENT_ID is required"
[ -n "$UPSTREAM" ] || fail "OPLIA_CONSOLE_API_UPSTREAM is required (e.g. http://oplia-api.oplia-system.svc.cluster.local)"

URL_RE='https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~%/-]*)?'
matches "$AUTHORITY" "$URL_RE" || fail "OPLIA_CONSOLE_AUTHORITY is not a plain http(s) URL"
case "$AUTHORITY" in
  https://*) ;;
  http://*)
    [ "$ALLOW_HTTP" = "true" ] || fail "OPLIA_CONSOLE_AUTHORITY must be https:// (http only with OPLIA_CONSOLE_ALLOW_HTTP_AUTHORITY=true, for the local dev login)" ;;
esac
matches "$CLIENT_ID" '[A-Za-z0-9._:/-]{1,200}' || fail "OPLIA_CONSOLE_CLIENT_ID has unexpected characters"
matches "$SCOPE" '[A-Za-z0-9._:/ -]{1,500}' || fail "OPLIA_CONSOLE_SCOPE has unexpected characters"
[ -z "$LABEL" ] || matches "$LABEL" '[A-Za-z0-9 ._()-]{1,60}' || fail "OPLIA_CONSOLE_ENVIRONMENT_LABEL has unexpected characters (max 60)"
matches "$UPSTREAM" 'https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?' || fail "OPLIA_CONSOLE_API_UPSTREAM must be scheme://host[:port] without a path"

# origin of the identity provider: the browser calls its discovery and token endpoints
AUTH_ORIGIN=$(printf '%s' "$AUTHORITY" | sed -E 's#^(https?://[^/]+).*#\1#')

# listen on IPv6 only where the kernel supports it (IPv4-only nodes would make nginx fail to start)
LISTEN6=""
[ -f /proc/net/if_inet6 ] && LISTEN6="listen [::]:8080;"

mkdir -p "$OUT"
cat > "$OUT/config.json" <<JSON
{
  "authority": "$AUTHORITY",
  "clientId": "$CLIENT_ID",
  "scope": "$SCOPE",
  "apiBase": "/api",
  "environmentLabel": "$LABEL"
}
JSON

cat > "$OUT/headers.conf" <<CONF
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' $AUTH_ORIGIN; form-action 'self' $AUTH_ORIGIN; frame-ancestors 'none'; base-uri 'none'; object-src 'none'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer" always;
add_header X-Frame-Options "DENY" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
CONF

cat > "$OUT/server.conf" <<CONF
server {
  listen 8080;
  $LISTEN6
  server_name _;
  root $HTML;
  index index.html;

  location = /healthz {
    access_log off;
    default_type text/plain;
    return 200 "ok\n";
  }

  location = /config.json {
    alias $OUT/config.json;
    default_type application/json;
    include $OUT/headers.conf;
    add_header Cache-Control "no-store" always;
  }

  location /assets/ {
    include $OUT/headers.conf;
    add_header Cache-Control "public, max-age=31536000, immutable" always;
    try_files \$uri =404;
  }

  location /api/ {
    proxy_pass $UPSTREAM/;
    proxy_http_version 1.1;
    proxy_set_header Host \$proxy_host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Forwarded-Prefix /api;
    proxy_connect_timeout 5s;
    proxy_read_timeout 60s;
    client_max_body_size 1m;
    proxy_hide_header Server;
    include $OUT/headers.conf;
    add_header Cache-Control "no-store" always;
  }

  location / {
    include $OUT/headers.conf;
    add_header Cache-Control "no-store" always;
    try_files \$uri /index.html;
  }
}
CONF

echo "oplia-console: identity provider $AUTH_ORIGIN, client $CLIENT_ID, API $UPSTREAM"
NGINX=${OPLIA_CONSOLE_NGINX:-nginx}
CONF_FILE=${OPLIA_CONSOLE_NGINX_CONF:-/etc/oplia-console/nginx.conf}
# -e stderr: never touch the compiled-in log path (the root filesystem is read-only)
"$NGINX" -e stderr -t -q -c "$CONF_FILE"
exec "$NGINX" -e stderr -c "$CONF_FILE" -g "daemon off;"
