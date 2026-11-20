"""Multi-cloud inventory of compute, storage and database resources with their tags.

Each source returns :class:`Resource` items. Tag keys are kept **exactly as stored** by the
cloud so the compliance check can be case-sensitive.

* AWS - service APIs (EC2 instances and EBS volumes, S3 buckets, RDS instances and clusters,
  DynamoDB tables). The Resource Groups Tagging API is *not* used here because it does not
  return resources that never had a tag, which are exactly the ones this scan must find.
* Azure - Azure Resource Manager ``resources.list`` filtered to compute/storage/database types.
* GCP - Cloud Asset Inventory ``search_all_resources``. GCP **labels** only allow lowercase keys,
  so labels are returned separately from Resource Manager **tags** (whose short names keep case).
* IBM Cloud - Global Search and Tagging API v3 with an IAM token from an API key. User tags
  are ``key:value`` strings and are split on the first ``:``.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from oplia_ctl.http import ResilientClient
from oplia_ctl.secrets import SecretProvider

log = logging.getLogger("oplia.finops.inventory")

Cloud = Literal["aws", "azure", "gcp", "ibm"]
Category = Literal["compute", "storage", "database"]


@dataclass(frozen=True)
class Resource:
    cloud: Cloud
    scope: str              # account / subscription / project / IBM account
    region: str
    category: Category
    resource_type: str      # native type, e.g. ec2:instance, Microsoft.Compute/disks
    resource_id: str        # ARN / ARM id / full resource name / CRN
    name: str
    tags: dict[str, str] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)  # GCP labels (lowercase keys only)
    size: str | None = None   # machine type / size where the listing API returns it (EC2: InstanceType)
    state: str | None = None  # lifecycle state where the listing API returns it (EC2 State.Name, GCP state)


class InventorySource(Protocol):
    name: str

    def scopes(self) -> list[str]:
        """Scopes this source covers (used to resolve findings for deleted resources)."""
        ...

    def list_resources(self) -> Iterator[Resource]: ...


def _aws_tags(tag_list: list[dict[str, str]] | None) -> dict[str, str]:
    return {t["Key"]: t.get("Value", "") for t in tag_list or []}


ClientFactory = Callable[[str, str | None], Any]


def _boto_client(service: str, region: str | None) -> Any:
    import boto3

    return boto3.client(service, region_name=region)


class AwsInventory:
    name = "aws"

    def __init__(self, regions: list[str], client_factory: ClientFactory = _boto_client) -> None:
        if not regions:
            raise ValueError("at least one AWS region is required")
        self._regions = regions
        self._client = client_factory
        self._account: str | None = None

    def _account_id(self) -> str:
        if self._account is None:
            self._account = str(self._client("sts", self._regions[0]).get_caller_identity()["Account"])
        return self._account

    def scopes(self) -> list[str]:
        return [self._account_id()]

    def list_resources(self) -> Iterator[Resource]:
        acct = self._account_id()
        for region in self._regions:
            ec2 = self._client("ec2", region)
            for page in ec2.get_paginator("describe_instances").paginate():
                for res in page["Reservations"]:
                    for i in res["Instances"]:
                        if i.get("State", {}).get("Name") in ("terminated", "shutting-down"):
                            continue
                        tags = _aws_tags(i.get("Tags"))
                        yield Resource("aws", acct, region, "compute", "ec2:instance",
                                       f"arn:aws:ec2:{region}:{acct}:instance/{i['InstanceId']}",
                                       tags.get("Name", i["InstanceId"]), tags,
                                       size=i.get("InstanceType"), state=i.get("State", {}).get("Name"))
            for page in ec2.get_paginator("describe_volumes").paginate():
                for v in page["Volumes"]:
                    tags = _aws_tags(v.get("Tags"))
                    yield Resource("aws", acct, region, "storage", "ec2:volume",
                                   f"arn:aws:ec2:{region}:{acct}:volume/{v['VolumeId']}",
                                   tags.get("Name", v["VolumeId"]), tags)
            rds = self._client("rds", region)
            for page in rds.get_paginator("describe_db_instances").paginate():
                for d in page["DBInstances"]:
                    yield Resource("aws", acct, region, "database", "rds:db", d["DBInstanceArn"],
                                   d["DBInstanceIdentifier"], _aws_tags(d.get("TagList")))
            for page in rds.get_paginator("describe_db_clusters").paginate():
                for c in page["DBClusters"]:
                    yield Resource("aws", acct, region, "database", "rds:cluster", c["DBClusterArn"],
                                   c["DBClusterIdentifier"], _aws_tags(c.get("TagList")))
            ddb = self._client("dynamodb", region)
            for page in ddb.get_paginator("list_tables").paginate():
                for table in page["TableNames"]:
                    arn = ddb.describe_table(TableName=table)["Table"]["TableArn"]
                    table_tags: dict[str, str] = {}
                    token: str | None = None
                    while True:
                        kw = {"ResourceArn": arn, **({"NextToken": token} if token else {})}
                        out = ddb.list_tags_of_resource(**kw)
                        table_tags.update(_aws_tags(out.get("Tags")))
                        token = out.get("NextToken")
                        if not token:
                            break
                    yield Resource("aws", acct, region, "database", "dynamodb:table", arn, table, table_tags)
        s3 = self._client("s3", self._regions[0])
        from botocore.exceptions import ClientError

        for b in s3.list_buckets().get("Buckets", []):
            bucket_tags: dict[str, str]
            try:
                bucket_tags = _aws_tags(s3.get_bucket_tagging(Bucket=b["Name"]).get("TagSet"))
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "NoSuchTagSet":
                    raise
                bucket_tags = {}
            yield Resource("aws", acct, "global", "storage", "s3:bucket", f"arn:aws:s3:::{b['Name']}",
                           b["Name"], bucket_tags)


AZURE_TYPES: dict[str, Category] = {
    "microsoft.compute/virtualmachines": "compute",
    "microsoft.compute/virtualmachinescalesets": "compute",
    "microsoft.containerservice/managedclusters": "compute",
    "microsoft.compute/disks": "storage",
    "microsoft.storage/storageaccounts": "storage",
    "microsoft.sql/servers/databases": "database",
    "microsoft.sql/managedinstances": "database",
    "microsoft.dbforpostgresql/flexibleservers": "database",
    "microsoft.dbformysql/flexibleservers": "database",
    "microsoft.documentdb/databaseaccounts": "database",
    "microsoft.cache/redis": "database",
}


def _azure_resource_client(subscription: str) -> Any:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resource import ResourceManagementClient

    return ResourceManagementClient(DefaultAzureCredential(), subscription)


class AzureInventory:
    name = "azure"

    def __init__(self, subscriptions: list[str],
                 client_factory: Callable[[str], Any] = _azure_resource_client) -> None:
        if not subscriptions:
            raise ValueError("at least one Azure subscription is required")
        self._subs = subscriptions
        self._client = client_factory

    def scopes(self) -> list[str]:
        return list(self._subs)

    def list_resources(self) -> Iterator[Resource]:
        for sub in self._subs:
            for r in self._client(sub).resources.list():
                rtype = str(r.type)
                cat = AZURE_TYPES.get(rtype.lower())
                if cat is None:
                    continue
                if rtype.lower() == "microsoft.sql/servers/databases" and str(r.name).endswith("/master"):
                    continue  # system database, not taggable by customers
                yield Resource("azure", sub, str(r.location or ""), cat, rtype, str(r.id), str(r.name),
                               dict(r.tags or {}))


GCP_ASSET_TYPES: dict[str, Category] = {
    "compute.googleapis.com/Instance": "compute",
    "container.googleapis.com/Cluster": "compute",
    "compute.googleapis.com/Disk": "storage",
    "storage.googleapis.com/Bucket": "storage",
    "sqladmin.googleapis.com/Instance": "database",
    "alloydb.googleapis.com/Cluster": "database",
    "spanner.googleapis.com/Instance": "database",
    "bigtableadmin.googleapis.com/Instance": "database",
    "redis.googleapis.com/Instance": "database",
}


def _gcp_asset_client() -> Any:
    from google.cloud import asset_v1

    return asset_v1.AssetServiceClient()


class GcpInventory:
    name = "gcp"

    def __init__(self, scopes: list[str], client_factory: Callable[[], Any] = _gcp_asset_client) -> None:
        for s in scopes:
            if not s.startswith(("projects/", "folders/", "organizations/")):
                raise ValueError(f"GCP scope {s!r} must be projects/<id>, folders/<n> or organizations/<n>")
        if not scopes:
            raise ValueError("at least one GCP scope is required")
        self._scopes = scopes
        self._client = client_factory

    def scopes(self) -> list[str]:
        return list(self._scopes)

    def list_resources(self) -> Iterator[Resource]:
        client = self._client()
        for scope in self._scopes:
            pager = client.search_all_resources(scope=scope, asset_types=list(GCP_ASSET_TYPES))
            for r in pager:
                tags: dict[str, str] = {}
                for t in getattr(r, "tags", None) or []:
                    # tag_key is "<org-or-project>/<ShortName>"; the short name keeps its case
                    key = str(t.tag_key).split("/", 1)[-1]
                    value = str(t.tag_value).split("/")[-1]
                    tags[key] = value
                state = str(getattr(r, "state", "") or "") or None  # e.g. RUNNING / TERMINATED
                yield Resource("gcp", scope, str(r.location or ""), GCP_ASSET_TYPES[str(r.asset_type)],
                               str(r.asset_type), str(r.name), str(r.display_name or r.name),
                               tags, dict(r.labels or {}), state=state)


IBM_IAM_URL = "https://iam.cloud.ibm.com/identity/token"
IBM_SEARCH_URL = "https://api.global-search-tagging.cloud.ibm.com/v3/resources/search"
DEFAULT_IBM_QUERIES: list[tuple[Category, str]] = [
    ("compute", "family:is AND type:instance"),
    ("compute", "type:k8-cluster"),
    ("storage", "family:is AND type:volume"),
    ("storage", "family:resource_controller AND service_name:cloud-object-storage"),
    ("database", "family:resource_controller AND service_name:databases-for-*"),
]


def ibm_tags(raw: list[str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for t in raw or []:
        key, _, value = str(t).partition(":")
        out[key] = value
    return out


class IbmInventory:
    name = "ibm"

    def __init__(self, *, account_id: str, secrets: SecretProvider, client: ResilientClient,
                 api_key_secret: str = "ibm_cloud_api_key",  # noqa: S107 - secret NAME
                 queries: list[tuple[Category, str]] | None = None,
                 page_size: int = 100) -> None:
        if not account_id:
            raise ValueError("IBM account id is required")
        self._account = account_id
        self._secrets = secrets
        self._client = client
        self._key_secret = api_key_secret
        self._queries = queries or DEFAULT_IBM_QUERIES
        self._page = page_size

    def scopes(self) -> list[str]:
        return [self._account]

    def _token(self) -> str:
        resp = self._client.request(
            "POST", IBM_IAM_URL, expected={200},
            data={"grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                  "apikey": self._secrets.get(self._key_secret)},
            headers={"Accept": "application/json"})
        return str(resp.json()["access_token"])

    def list_resources(self) -> Iterator[Resource]:
        headers = {"Authorization": f"Bearer {self._token()}", "Accept": "application/json"}
        params = {"account_id": self._account, "limit": str(self._page)}
        seen: set[str] = set()
        for category, query in self._queries:
            body: dict[str, Any] = {"query": query, "fields": ["crn", "name", "type", "region", "tags"]}
            while True:
                data = self._client.request("POST", IBM_SEARCH_URL, params=params, json=body,
                                            headers=headers, expected={200}).json()
                items = data.get("items") or []
                for it in items:
                    crn = str(it["crn"])
                    if crn in seen:
                        continue
                    seen.add(crn)
                    yield Resource("ibm", self._account, str(it.get("region") or ""), category,
                                   str(it.get("type") or ""), crn, str(it.get("name") or crn),
                                   ibm_tags(it.get("tags")))
                cursor = data.get("search_cursor")
                if not items or not cursor or len(items) < self._page:
                    break
                body = {"search_cursor": cursor}  # documented: only the cursor after the first call
