"""Process entry point for the CDC hydration sidecar (``oplia-migration-hydrator``).

Configuration (environment, all JSON where noted):

* ``OPLIA_HYDRATOR_SPEC``     - HydrationSpec (JSON)
* ``OPLIA_HYDRATOR_TARGET``   - {"kind": ..., ...} target settings (JSON, see ``build_writer``)
* ``OPLIA_HYDRATOR_TOPICS``   - comma-separated Debezium topics
* ``OPLIA_HYDRATOR_KAFKA``    - librdkafka settings (JSON; bootstrap.servers, security.*); secrets in it are
  secret NAMES prefixed ``secret:`` and resolved from the secret provider
* ``OPLIA_HYDRATOR_EMBED_PROVIDER`` - name of an OPLIA_MIGRATION_AI_PROVIDERS entry (vector mode)
"""

from __future__ import annotations

import json
import logging
import os
import signal
from typing import Any

from oplia_ctl.migration.targets import (
    AzureSearchWriter,
    BigQueryMergeWriter,
    BigtableWriter,
    CosmosWriter,
    CqlWriter,
    DynamoWriter,
    FirestoreWriter,
    GremlinWriter,
    KustoWriter,
    MongoWriter,
    OpenSearchWriter,
    PgVectorWriter,
    RedisWriter,
    RedshiftMergeWriter,
    SpannerWriter,
    TargetWriter,
    TimestreamWriter,
)

KINDS = ("mongo", "cosmos", "firestore", "dynamodb", "bigtable", "cql", "spanner", "redis", "gremlin", "timestream",
         "kusto", "bigquery", "redshift", "opensearch", "azure_search", "pgvector")


def build_writer(t: dict[str, Any], secrets: Any, http: Any) -> TargetWriter:   # pragma: no cover - SDK wiring
    k = t.get("kind")
    if k == "mongo":
        from pymongo import MongoClient

        return MongoWriter(MongoClient(secrets.get(t["uri_secret"])), t["database"])
    if k == "cosmos":
        from azure.cosmos import CosmosClient
        from azure.identity import DefaultAzureCredential

        db = CosmosClient(t["endpoint"], credential=DefaultAzureCredential()).get_database_client(t["database"])
        return CosmosWriter({c: db.get_container_client(c) for c in t["containers"]}, t.get("partition_keys", {}))
    if k == "firestore":
        from google.cloud import firestore

        return FirestoreWriter(firestore.Client(project=t["project"], database=t.get("database", "(default)")))
    if k == "dynamodb":
        import boto3

        return DynamoWriter(boto3.client("dynamodb", region_name=t["region"]), t["table"], t["keys"])
    if k == "bigtable":
        from google.cloud import bigtable

        inst = bigtable.Client(project=t["project"]).instance(t["instance"])  # type: ignore[no-untyped-call]
        return BigtableWriter({n: inst.table(n) for n in t["tables"]})
    if k == "cql":
        from cassandra.auth import PlainTextAuthProvider
        from cassandra.cluster import Cluster

        user, _, pw = secrets.get(t["credentials_secret"]).partition(":")
        import ssl

        ctx = ssl.create_default_context(cafile=t.get("ca_file"))
        cluster = Cluster(t["hosts"], port=int(t.get("port", 9142)), ssl_context=ctx,
                          auth_provider=PlainTextAuthProvider(user, pw))
        return CqlWriter(cluster.connect(), t["keyspace"], t["keys"])
    if k == "spanner":
        from google.cloud import spanner

        client = spanner.Client(project=t["project"])
        return SpannerWriter(client.instance(t["instance"]).database(t["database"]))  # type: ignore[no-untyped-call]
    if k == "redis":
        import redis

        return RedisWriter(redis.Redis.from_url(secrets.get(t["url_secret"])), t.get("ttl_seconds"),
                           t.get("lookups"))
    if k == "gremlin":
        from gremlin_python.driver.client import Client

        user, _, pw = secrets.get(t["credentials_secret"]).partition(":") if t.get("credentials_secret") else ("", "",
                                                                                                             "")
        return GremlinWriter(Client(t["url"], "g", username=user or None, password=pw or None),
                             t.get("partition_property"))
    if k == "timestream":
        import boto3

        return TimestreamWriter(boto3.client("timestream-write", region_name=t["region"]), t["database"], t["spec"])
    if k == "kusto":
        from azure.identity import DefaultAzureCredential

        cred = DefaultAzureCredential()
        return KustoWriter(http, t["cluster_url"], t["database"],
                           lambda: str(cred.get_token(f"{t['cluster_url'].rstrip('/')}/.default").token))
    if k == "bigquery":
        from google.cloud import bigquery

        return BigQueryMergeWriter(bigquery.Client(project=t["project"]), t["dataset"], t["keys"])
    if k == "redshift":
        import boto3

        return RedshiftMergeWriter(boto3.client("redshift-data", region_name=t["region"]), t["target"],
                                   t["database"], t["schema"], t["keys"])
    if k == "opensearch":
        return OpenSearchWriter(http, t["endpoint"])
    if k == "azure_search":
        return AzureSearchWriter(http, t["service_url"], lambda: {"api-key": secrets.get(t["key_secret"])})
    if k == "pgvector":
        import psycopg

        return PgVectorWriter(psycopg.connect(secrets.get(t["dsn_secret"]), autocommit=True), t["keys"])
    raise ValueError(f"target kind must be one of {KINDS}")


def main() -> None:  # pragma: no cover - process wiring, exercised in deployment
    from confluent_kafka import Consumer

    from oplia_ctl.config import get_settings
    from oplia_ctl.db import make_engine, make_session_factory
    from oplia_ctl.http import ResilientClient
    from oplia_ctl.migration.hydrate import HydrationSpec, Hydrator, run_kafka
    from oplia_ctl.secrets import build_secret_provider

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    secrets = build_secret_provider(settings.secret_provider)
    spec = HydrationSpec.model_validate_json(os.environ["OPLIA_HYDRATOR_SPEC"])
    http = ResilientClient(timeout=30.0, max_retries=3)
    writer = build_writer(json.loads(os.environ["OPLIA_HYDRATOR_TARGET"]), secrets, http)
    embed = None
    if os.environ.get("OPLIA_HYDRATOR_EMBED_PROVIDER"):
        from oplia_ctl.migration.ai import build_providers
        from oplia_ctl.migration.config import MigrationSettings

        providers = build_providers(MigrationSettings().ai_providers, http, secrets)
        p = providers[os.environ["OPLIA_HYDRATOR_EMBED_PROVIDER"]]
        embed = p.embed
    kconf = {k: (secrets.get(v[7:]) if isinstance(v, str) and v.startswith("secret:") else v)
             for k, v in json.loads(os.environ["OPLIA_HYDRATOR_KAFKA"]).items()}
    kconf.update({"group.id": f"oplia-hydrator-{spec.pipeline}", "enable.auto.commit": False,
                  "auto.offset.reset": "earliest"})
    stopping = {"v": False}
    signal.signal(signal.SIGTERM, lambda *_: stopping.update(v=True))
    hydrator = Hydrator(spec, writer, make_session_factory(make_engine(settings.database_url)), embed)
    consumer = Consumer(kconf)
    try:
        stats = run_kafka(hydrator, consumer, os.environ["OPLIA_HYDRATOR_TOPICS"].split(","),
                          stop=lambda: stopping["v"])
    finally:
        consumer.close()
    logging.getLogger("oplia.migration").info("hydrator stopped: %s", stats)
