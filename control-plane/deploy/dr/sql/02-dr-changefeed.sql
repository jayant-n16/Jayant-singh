-- Asynchronous DR channel: changefeed -> Kafka topic "cdc.*" -> oplia-dr-breaker -> topic "dr.*"
-- -> standby consumers. The broker credentials live in an external connection, not in SQL history.
CREATE EXTERNAL CONNECTION IF NOT EXISTS dr_kafka
  AS 'kafka://kafka-bootstrap.oplia-data.svc:9093?tls_enabled=true&sasl_enabled=true&sasl_mechanism=SCRAM-SHA-512&sasl_user=crdb-cdc&sasl_password=REPLACE_FROM_VAULT&topic_prefix=cdc.';

CREATE CHANGEFEED FOR TABLE app.public.accounts, app.public.orders
  INTO 'external://dr_kafka'
  WITH updated,
       resolved = '10s',
       diff,                          -- "before" image, so updates are recognisable
       on_error = 'pause',            -- a broken sink pauses the feed instead of losing its position
       schema_change_policy = 'stop', -- schema changes (incl. DROP TABLE) stop the feed for review
       initial_scan = 'no';
