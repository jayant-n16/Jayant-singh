# Bootstrap root that creates the shared remote-state backends for OPLIA pipelines.
#
# This root itself starts on local state (a backend cannot store its own bootstrap state
# before it exists). After the first apply, migrate it: add a `backend "s3" {}` block and
# run `terraform init -migrate-state` with the values from the outputs.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40, < 7.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.9, < 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

provider "azurerm" {
  features {}
  subscription_id     = var.azure_subscription_id
  storage_use_azuread = true
}

module "aws_state" {
  source = "../../modules/aws-state-backend"

  bucket_name       = var.aws_state_bucket_name
  lock_table_name   = "terraform-state-lock"
  access_log_bucket = var.aws_access_log_bucket
  tags              = var.tags
}

module "azure_state" {
  source = "../../modules/azure-state-backend"

  resource_group_name             = var.azure_resource_group_name
  location                        = var.azure_location
  storage_account_name            = var.azure_storage_account_name
  allowed_ip_ranges               = var.azure_allowed_ip_ranges
  state_contributor_principal_ids = var.azure_pipeline_principal_ids
  tags                            = var.tags
}
