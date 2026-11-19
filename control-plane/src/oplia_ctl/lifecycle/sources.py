"""Discovery of resources tagged with ``LifecycleTTL``.

* AWS: Resource Groups Tagging API ``GetResources`` per region (paginated).
  The account id comes from each ARN; global ARNs without an account (for
  example S3 buckets) use the caller account from STS.
* Azure: ``resources.list`` per subscription filtered on the tag name.

Each source returns plain :class:`TaggedResource` values, so grouping and the
expiry decision are independent of any SDK.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from oplia_ctl.lifecycle.stacks import TAG_TTL, TaggedResource


class ResourceSource(Protocol):
    def list_resources(self) -> list[TaggedResource]: ...


def _arn_account(arn: str) -> str:
    parts = arn.split(":")
    return parts[4] if len(parts) > 5 else ""


class AwsTaggedSource:
    def __init__(
        self,
        regions: list[str],
        client_factory: Callable[[str, str], Any] | None = None,
    ) -> None:
        if not regions:
            raise ValueError("at least one AWS region is required")
        self._regions = regions
        self._factory = client_factory or _boto_client

    def list_resources(self) -> list[TaggedResource]:
        caller = str(self._factory("sts", self._regions[0]).get_caller_identity()["Account"])
        out: list[TaggedResource] = []
        seen: set[str] = set()
        for region in self._regions:
            paginator = self._factory("resourcegroupstaggingapi", region).get_paginator("get_resources")
            for page in paginator.paginate(TagFilters=[{"Key": TAG_TTL}]):
                for item in page.get("ResourceTagMappingList", []):
                    arn = str(item["ResourceARN"])
                    if arn in seen:  # global resources can be returned by several regions
                        continue
                    seen.add(arn)
                    tags = {str(t["Key"]): str(t["Value"]) for t in item.get("Tags", [])}
                    out.append(TaggedResource("aws", _arn_account(arn) or caller, arn, tags))
        return out


def _boto_client(service: str, region: str) -> Any:
    import boto3

    return boto3.client(service, region_name=region)


class AzureTaggedSource:
    def __init__(
        self,
        subscriptions: list[str],
        client_factory: Callable[[str], Any] | None = None,
    ) -> None:
        if not subscriptions:
            raise ValueError("at least one Azure subscription is required")
        self._subs = subscriptions
        self._factory = client_factory or _azure_client

    def list_resources(self) -> list[TaggedResource]:
        out: list[TaggedResource] = []
        for sub in self._subs:
            client = self._factory(sub)
            for res in client.resources.list(filter=f"tagName eq '{TAG_TTL}'"):
                out.append(TaggedResource("azure", sub, str(res.id), dict(res.tags or {})))
        return out


def _azure_client(subscription_id: str) -> Any:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resource import ResourceManagementClient

    return ResourceManagementClient(DefaultAzureCredential(), subscription_id)
