-- Run once against any node after all four clouds have joined (cockroach sql --certs-dir=...).
-- Region names come from the --locality "region" tier set in each cloud overlay.
SET CLUSTER SETTING kv.rangefeed.enabled = true;          -- required by changefeeds (DR channel)

CREATE DATABASE IF NOT EXISTS app;
ALTER DATABASE app SET PRIMARY REGION "aws-us-east-1";
ALTER DATABASE app ADD REGION "azure-eastus2";
ALTER DATABASE app ADD REGION "gcp-us-central1";
ALTER DATABASE app ADD REGION "ibm-us-south";
-- Survive the loss of a whole cloud: every range keeps replicas in >= 3 regions (needs >= 3 regions).
ALTER DATABASE app SURVIVE REGION FAILURE;

-- Writes in this cluster are committed by Raft quorum across clouds (RPO = 0 for node / zone /
-- cloud loss). A logical error (DROP TABLE, mass UPDATE) is ALSO committed everywhere at once:
-- the circuit breaker cannot stop that inside one cluster - it protects the asynchronous DR copy
-- fed by 02-dr-changefeed.sql.
