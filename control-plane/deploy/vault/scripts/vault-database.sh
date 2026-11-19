#!/usr/bin/env bash
# Dynamic database credentials. Each connection needs an admin DSN that Vault uses to create
# short-lived users. Passwords are read from files (never on the command line / shell history).
#   PG_HOST PG_PORT PG_DB PG_ADMIN_USER PG_ADMIN_PASSWORD_FILE   (required for PostgreSQL)
#   MYSQL_HOST MYSQL_PORT MYSQL_ADMIN_USER MYSQL_ADMIN_PASSWORD_FILE   (optional)
#   MONGO_URI_HOSTS MONGO_ADMIN_USER MONGO_ADMIN_PASSWORD_FILE   (optional)
set -euo pipefail
V=${VAULT_CLI:-vault}
TTL=${CRED_TTL:-1h}; MAX_TTL=${CRED_MAX_TTL:-24h}

$V write database/config/app-prod-postgres plugin_name=postgresql-database-plugin \
  allowed_roles="app-prod-postgres" \
  connection_url="postgresql://{{username}}:{{password}}@${PG_HOST}:${PG_PORT:-5432}/${PG_DB}?sslmode=${PG_SSLMODE:-verify-full}" \
  username="$PG_ADMIN_USER" password=@"$PG_ADMIN_PASSWORD_FILE"
$V write -force database/rotate-root/app-prod-postgres >/dev/null 2>&1 || echo "note: rotate-root skipped (run it once the admin account is dedicated to Vault)"
$V write database/roles/app-prod-postgres db_name=app-prod-postgres default_ttl="$TTL" max_ttl="$MAX_TTL" \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' INHERIT; GRANT app_rw TO \"{{name}}\";" \
  revocation_statements="REASSIGN OWNED BY \"{{name}}\" TO app_owner; DROP OWNED BY \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";"

if [ -n "${MYSQL_HOST:-}" ]; then
  $V write database/config/app-prod-mysql plugin_name=mysql-database-plugin allowed_roles="app-prod-mysql" \
    connection_url="{{username}}:{{password}}@tcp(${MYSQL_HOST}:${MYSQL_PORT:-3306})/" \
    username="$MYSQL_ADMIN_USER" password=@"$MYSQL_ADMIN_PASSWORD_FILE"
  $V write database/roles/app-prod-mysql db_name=app-prod-mysql default_ttl="$TTL" max_ttl="$MAX_TTL" \
    creation_statements="CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'; GRANT SELECT, INSERT, UPDATE, DELETE ON app.* TO '{{name}}'@'%';" \
    revocation_statements="DROP USER IF EXISTS '{{name}}'@'%';"
fi

if [ -n "${MONGO_URI_HOSTS:-}" ]; then
  $V write database/config/app-prod-mongodb plugin_name=mongodb-database-plugin allowed_roles="app-prod-mongodb" \
    connection_url="mongodb://{{username}}:{{password}}@${MONGO_URI_HOSTS}/admin?tls=true" \
    username="$MONGO_ADMIN_USER" password=@"$MONGO_ADMIN_PASSWORD_FILE"
  $V write database/roles/app-prod-mongodb db_name=app-prod-mongodb default_ttl="$TTL" max_ttl="$MAX_TTL" \
    creation_statements='{ "db": "admin", "roles": [{ "role": "readWrite", "db": "app" }] }'
fi
echo "database engine configured"
