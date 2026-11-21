variable "aws_region" {
  description = "Region for the state bucket and lock table."
  type        = string
}

variable "aws_state_bucket_name" {
  description = "Globally unique S3 bucket name for Terraform state."
  type        = string
}

variable "aws_access_log_bucket" {
  description = "Optional existing bucket for S3 server access logs."
  type        = string
  default     = null
}

variable "azure_subscription_id" {
  description = "Subscription that hosts the state storage account."
  type        = string
}

variable "azure_resource_group_name" {
  description = "Resource group for the state storage account."
  type        = string
}

variable "azure_location" {
  description = "Azure region for the state storage account."
  type        = string
}

variable "azure_storage_account_name" {
  description = "Globally unique storage account name."
  type        = string
}

variable "azure_allowed_ip_ranges" {
  description = "Runner IPs/CIDRs allowed to reach the state account."
  type        = list(string)
  default     = []
}

variable "azure_pipeline_principal_ids" {
  description = "Object IDs of pipeline identities that read and write state."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default = {
    ManagedBy = "oplia"
    Purpose   = "terraform-state"
  }
}
