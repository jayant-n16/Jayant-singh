# Remote Terraform state on Azure: a hardened StorageV2 account and a private container.
#
# Locking: the azurerm backend locks state with a native blob lease on every operation.
# There is nothing to switch on; what matters is that every run uses this backend (never
# local state) so the lease is always taken. This replaces the "lease-locking enabled"
# setting mentioned in the source document, which does not exist as a separate option.
#
# Authentication: shared keys are disabled; pipelines use Microsoft Entra ID (OIDC) and
# need "Storage Blob Data Contributor" on this account (state_contributor_principal_ids).
# With azurerm >= 4.9 the container is managed through Azure Resource Manager
# (storage_account_id), so disabling shared keys does not break this module.

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.9, < 5.0"
    }
  }
}

resource "azurerm_resource_group" "state" {
  count    = var.create_resource_group ? 1 : 0
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

locals {
  resource_group_name = var.create_resource_group ? azurerm_resource_group.state[0].name : var.resource_group_name
}

resource "azurerm_storage_account" "state" {
  #checkov:skip=CKV_AZURE_59:Public endpoint is a variable (default on, for hosted runners) and is always fenced by network_rules default Deny.
  #checkov:skip=CKV2_AZURE_33:Private endpoint is site-specific; set public_network_access_enabled=false and add one in the caller.
  #checkov:skip=CKV_AZURE_206:Replication is configurable; default ZRS because GZRS is not offered in every region.
  #checkov:skip=CKV_AZURE_33:Account holds only blob state; the queue service is unused.
  #checkov:skip=CKV2_AZURE_1:Platform keys plus infrastructure (double) encryption; CMK would add a Key Vault dependency to bootstrap.
  name                              = var.storage_account_name
  resource_group_name               = local.resource_group_name
  location                          = var.location
  account_kind                      = "StorageV2"
  account_tier                      = "Standard"
  account_replication_type          = var.replication_type
  min_tls_version                   = "TLS1_2"
  https_traffic_only_enabled        = true
  allow_nested_items_to_be_public   = false
  shared_access_key_enabled         = false
  default_to_oauth_authentication   = true
  infrastructure_encryption_enabled = true
  public_network_access_enabled     = var.public_network_access_enabled # fenced by network_rules below

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = var.soft_delete_days
    }
    container_delete_retention_policy {
      days = var.soft_delete_days
    }
  }

  network_rules {
    default_action             = var.network_default_action
    bypass                     = ["AzureServices"]
    ip_rules                   = var.allowed_ip_ranges
    virtual_network_subnet_ids = var.allowed_subnet_ids
  }

  tags = var.tags
}

resource "azurerm_storage_container" "state" {
  #checkov:skip=CKV2_AZURE_21:Blob read logging is provided by azurerm_monitor_diagnostic_setting.blob when log_analytics_workspace_id is set.
  name                  = var.container_name
  storage_account_id    = azurerm_storage_account.state.id
  container_access_type = "private"
}

resource "azurerm_management_lock" "state" {
  name       = "oplia-state-no-delete"
  scope      = azurerm_storage_account.state.id
  lock_level = "CanNotDelete"
  notes      = "Holds Terraform state for OPLIA-managed infrastructure. Remove deliberately."
}

resource "azurerm_role_assignment" "state" {
  for_each             = toset(var.state_contributor_principal_ids)
  scope                = azurerm_storage_account.state.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = each.value
}

resource "azurerm_monitor_diagnostic_setting" "blob" {
  count                      = var.log_analytics_workspace_id == null ? 0 : 1
  name                       = "oplia-state-blob-audit"
  target_resource_id         = "${azurerm_storage_account.state.id}/blobServices/default"
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category = "StorageRead"
  }
  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }
}
