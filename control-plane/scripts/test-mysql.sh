#!/usr/bin/env bash
# Start a throwaway MySQL 8 server for the DR read-only-lock integration tests.
# Usage: scripts/test-mysql.sh <workdir> [port]  -> prints export lines for the test run.
set -euo pipefail
D=${1:?workdir}; PORT=${2:-53306}
rm -rf "$D"; mkdir -p "$D/data" "$D/run"
RUNAS=()
if [ "$(id -u)" = "0" ]; then chown -R mysql:mysql "$D"; RUNAS=(--user=mysql); fi
mysqld --no-defaults "${RUNAS[@]}" --initialize-insecure --datadir="$D/data" >"$D/init.log" 2>&1 || { cat "$D/init.log" >&2; exit 1; }
mysqld --no-defaults "${RUNAS[@]}" --datadir="$D/data" --port="$PORT" --bind-address=127.0.0.1 \
  --socket="$D/run/mysqld.sock" --pid-file="$D/run/mysqld.pid" --mysqlx=OFF --log-error="$D/error.log" \
  --server-id=2 >/dev/null 2>&1 &
for _ in $(seq 1 100); do [ -S "$D/run/mysqld.sock" ] && break; sleep 0.2; done
PW=$(openssl rand -hex 16)
mysql --no-defaults -uroot --socket="$D/run/mysqld.sock" <<SQL
CREATE USER 'oplia_dr'@'127.0.0.1' IDENTIFIED BY '$PW';
GRANT SYSTEM_VARIABLES_ADMIN, REPLICATION_SLAVE_ADMIN, REPLICATION CLIENT ON *.* TO 'oplia_dr'@'127.0.0.1';
GRANT SELECT ON performance_schema.* TO 'oplia_dr'@'127.0.0.1';
CREATE DATABASE app;
CREATE USER 'app'@'127.0.0.1' IDENTIFIED BY '$PW';
GRANT ALL ON app.* TO 'app'@'127.0.0.1';
CREATE DATABASE app_src;
CREATE DATABASE app_dr;
CREATE USER 'oplia_cc'@'127.0.0.1' IDENTIFIED BY '$PW';
GRANT ALL ON app_src.* TO 'oplia_cc'@'127.0.0.1';
GRANT ALL ON app_dr.* TO 'oplia_cc'@'127.0.0.1';
GRANT REPLICATION CLIENT, REPLICATION_SLAVE_ADMIN ON *.* TO 'oplia_cc'@'127.0.0.1';
SQL
echo "export OPLIA_TEST_MYSQL_PORT=$PORT"
echo "export OPLIA_TEST_MYSQL_PW=$PW"
