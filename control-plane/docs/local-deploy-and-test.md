# Deploy and test the control plane and the migration engine on a Windows laptop (WSL)

These steps were run end to end on Ubuntu 24.04 (the same packages WSL installs) with PostgreSQL 16 and
Python 3.13; the output of the last step is shown so you can compare. They use native packages, not Docker:
no Docker was available where they were verified, so no `docker compose` file is offered here. Kafka,
Debezium and the cloud services are not part of this local test (see "What this does not test").

Run everything in **one WSL (Ubuntu) terminal** unless a step says otherwise. Commands in PowerShell are only
in step 1.

## 1. WSL (PowerShell, once)

```powershell
wsl --install -d Ubuntu-24.04
wsl -d Ubuntu-24.04
```

## 2. Packages

```bash
sudo apt-get update
sudo apt-get install -y git python3-venv python3-dev postgresql-16 redis-server curl nodejs npm
```

## 3. PostgreSQL with logical replication (needed for CDC and the lag probe)

```bash
sudo sed -i "s/^#\?wal_level.*/wal_level = logical/" /etc/postgresql/16/main/postgresql.conf
sudo service postgresql restart
sudo -u postgres psql -c "SHOW wal_level"                       # must print: logical
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'postgres'"
```

## 4. Get the code and install

```bash
git clone https://github.com/jayant-n16/Jayant-singh.git
cd Jayant-singh && git checkout feature/control-plane && cd control-plane
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,postgres,dr]"
```

## 5. Test databases (a source, a copy, and an empty scratch database)

```bash
export PGPASSWORD=postgres
for db in shop_src shop_target shop_scratch; do
  psql -h 127.0.0.1 -U postgres -c "DROP DATABASE IF EXISTS $db WITH (FORCE)" -c "CREATE DATABASE $db"
done
for db in shop_src shop_target; do
  psql -h 127.0.0.1 -U postgres -d $db -c "CREATE TABLE customers (id int PRIMARY KEY, email text);
    CREATE TABLE orders (id bigint PRIMARY KEY, customer_id int REFERENCES customers(id), total numeric(12,2));
    INSERT INTO customers SELECT g, 'c'||g||'@x' FROM generate_series(1,100) g;
    INSERT INTO orders SELECT g, g%100+1, g*1.5 FROM generate_series(1,20000) g;"
done
```

## 6. Settings (save as `~/oplia-env.sh`, then `. ~/oplia-env.sh` in every terminal)

```bash
export OPLIA_ENVIRONMENT=dev OPLIA_DRY_RUN=false
export OPLIA_DATABASE_URL=sqlite:///$HOME/oplia-control.db
export OPLIA_OIDC_ISSUER=http://127.0.0.1:8090/ OPLIA_OIDC_AUDIENCE=oplia-api OPLIA_OIDC_JWKS_URL=http://127.0.0.1:8090/jwks
export OPLIA_SECRET_WEBHOOK_HMAC_SECRET=local-dev-webhook-secret
export OPLIA_DATABASES='[{"name":"shop-src","engine":"postgres","cloud":"aws","role":"primary","dsn_secret":"shop_src_dsn","database":"shop_src"},{"name":"shop-target","engine":"postgres","cloud":"gcp","role":"replica","dr_of":"shop-src","dsn_secret":"shop_target_dsn","database":"shop_target"},{"name":"shop-scratch","engine":"postgres","cloud":"gcp","role":"primary","dsn_secret":"shop_scratch_dsn","database":"shop_scratch"}]'
export OPLIA_SECRET_SHOP_SRC_DSN=postgresql://postgres:postgres@127.0.0.1:5432/shop_src
export OPLIA_SECRET_SHOP_TARGET_DSN=postgresql://postgres:postgres@127.0.0.1:5432/shop_target
export OPLIA_SECRET_SHOP_SCRATCH_DSN=postgresql://postgres:postgres@127.0.0.1:5432/shop_scratch
export OPLIA_MIGRATION_ONLINE_DDL=true OPLIA_MIGRATION_SYNTHESIS=true OPLIA_MIGRATION_PARITY=true OPLIA_MIGRATION_LAG_PROBE=true
```

`OPLIA_DRY_RUN=false` makes approved proposals really run (the default records what they would do). The
`OPLIA_SECRET_*` variables are the local stand-in for Vault; never use this in a shared environment.

## 7. Start the dev login and the API (in the background, so Ctrl+C does not stop them)

```bash
. ~/oplia-env.sh && cd ~/Jayant-singh/control-plane && . .venv/bin/activate
nohup oplia-dev-idp > ~/idp.log 2>&1 &
nohup uvicorn oplia_ctl.main:app --host 127.0.0.1 --port 8000 > ~/api.log 2>&1 &
sleep 3; curl -s http://127.0.0.1:8000/healthz          # {"status":"ok"}
```

## 8. Run the migration smoke test

It signs in as bob (operator) and alice (approver) through the dev login, and for each job proposes it (bob),
approves it (alice), executes it (bob), runs the job worker and prints the result.

```bash
python scripts/migration-smoke.py
```

Expected output (from the verification run):

```
{"job": "schema_synthesis", "status": "SUCCEEDED", "error": null, "validation": {"database": "shop-scratch", "statements": 3, "failed": 0}}
{"job": "schema_change", "status": "SUCCEEDED", "error": null, "rows_backfilled": 20000, "checks": [{"check": "index ix_orders_customer is valid", "offending_rows": 0}, {"check": "total__oplia_new matches total on every row", "offending_rows": 0}]}
{"job": "parity_check", "status": "SUCCEEDED", "error": null, "result": {"tables": {"orders": {"source_rows": 20000, "target_rows": 20000, "columns_compared": 3, "columns_not_on_target": ["total__oplia_new"], "differing_buckets": 0, "status": "MATCH"}}, "schema": [], "status": "MATCH"}}
```

## 9. The console

```bash
cd ~/Jayant-singh/control-plane/console
npx -y npm@11.21.1 ci
nohup npx vite --host 127.0.0.1 > ~/vite.log 2>&1 &
```

Open http://localhost:5173 in Windows, sign in as **bob**, open **Migration**. The jobs from step 8 are listed
with their results. Propose a new job from there, sign out, sign in as **alice** to approve it, then as **bob**
to execute it, and run `oplia-dr-job-worker` in WSL to advance it.

## 10. The full test suite (optional, ~10 minutes)

```bash
cd ~/Jayant-singh/control-plane
psql -h 127.0.0.1 -U postgres -c "CREATE DATABASE oplia_test"
OPLIA_TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:5432/oplia_test \
OPLIA_TEST_PG_LOGICAL_URL=postgresql://postgres:postgres@127.0.0.1:5432/oplia_test pytest -q
```

Tests that need MySQL, MongoDB, OpenBao, Envoy or Redis skip themselves when those are not configured; CI
runs all of them (see `.github/workflows/control-plane-ci.yml` for how each one is started).

## Stopping

```bash
pkill -f oplia-dev-idp; pkill -f "uvicorn oplia_ctl.main:app"; pkill -f vite
```

## What this does not test

Kafka, Debezium and Kafka Connect; AWS DMS, Datastream and Azure DMS; Envoy cutover (the test suite runs it
when `OPLIA_TEST_ENVOY_BIN` points to an Envoy binary); and every cloud target. None of those were run
against a real cloud account.
