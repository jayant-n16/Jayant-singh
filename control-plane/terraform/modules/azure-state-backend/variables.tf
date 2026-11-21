variable "resource_group_name" {
  description = "Resource group holding the state storage account."
  type        = string
}

variable "create_resource_group" {
  description = "Create the resource group (true) or use an existing one (false)."
  type        = bool
  default     = true
}

variable "location" {
  description = "Azure region, e.g. eastus2."
  type        = string
}

variable "storage_account_name" {
  description = "Globally unique storage account name (3-24 lowercase letters and digits)."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9]{3,24}$", var.storage_account_name))
    error_message = "storage_account_name must be 3-24 lowercase letters and digits."
  }
}

variable "container_name" {
  description = "Blob container for state files."
  type        = string
  default     = "tfstate"
  validation {
    condition     = can(regex("^[a-z0-9](?:[a-z0-9]|-[a-z0-9]){2,62}$", var.container_name))
    error_message = "container_name must be 3-63 lowercase letters, digits and single hyphens."
  }
}

variable "replication_type" {
  description = "Storage replication. ZRS or GZRS recommended for state."
  type        = string
  default     = "ZRS"
  validation {
    condition     = contains(["LRS", "ZRS", "GRS", "RAGRS", "GZRS", "RAGZRS"], var.replication_type)
    error_message = "replication_type must be one of LRS, ZRS, GRS, RAGRS, GZRS, RAGZRS."
  }
}

variable "soft_delete_days" {
  description = "Retention for deleted blobs and containers (recovery from accidental deletion)."
  type        = number
  default     = 30
  validation {
    condition     = var.soft_delete_days >= 7 && var.soft_delete_days <= 365
    error_message = "soft_delete_days must be between 7 and 365."
  }
}

variable "network_default_action" {
  description = "Network rule default. Deny (recommended) admits only allowed_ip_ranges / allowed_subnet_ids."
  type        = string
  default     = "Deny"
  validation {
    condition     = contains(["Allow", "Deny"], var.network_default_action)
    error_message = "network_default_action must be Allow or Deny."
  }
}

variable "public_network_access_enabled" {
  description = "Keep the public endpoint (restricted by network rules). Set false when runners reach state via a private endpoint."
  type        = bool
  default     = true
}

variable "log_analytics_workspace_id" {
  description = "Optional Log Analytics workspace for blob read/write/delete audit logs."
  type        = string
  default     = null
}

variable "allowed_ip_ranges" {
  description = "Public IPs/CIDRs of pipeline runners allowed to reach state (needed when default action is Deny)."
  type        = list(string)
  default     = []
}

variable "allowed_subnet_ids" {
  description = "Subnet IDs (with the Microsoft.Storage service endpoint) allowed to reach state."
  type        = list(string)
  default     = []
}

variable "state_contributor_principal_ids" {
  description = "Object IDs of pipeline identities granted Storage Blob Data Contributor."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
