variable "name_prefix" {
  description = "Prefix for connection names."
  type        = string
}

variable "primary_port_uuid" {
  description = "Equinix Fabric port UUID for primary legs."
  type        = string
}

variable "secondary_port_uuid" {
  description = "Equinix Fabric port UUID for secondary legs (a different port/device for diversity)."
  type        = string
}

variable "notification_emails" {
  description = "Addresses Equinix notifies about connection state."
  type        = list(string)
  validation {
    condition     = length(var.notification_emails) > 0
    error_message = "At least one notification address is required."
  }
}

variable "purchase_order_number" {
  description = "Purchase order number (optional)."
  type        = string
  default     = null
}

variable "connections" {
  description = "Connections by key. cloud is aws, azure, gcp or ibm. See main.tf for authentication_key per cloud."
  type = map(object({
    cloud                          = string
    bandwidth_mbps                 = number
    metro_code                     = string
    seller_region                  = optional(string)
    service_profile_uuid           = string
    secondary_service_profile_uuid = optional(string)
    authentication_key             = string
    secondary_authentication_key   = optional(string)
    vlan_tag                       = number
    secondary_vlan_tag             = optional(number)
    redundant                      = optional(bool, true)
  }))
  validation {
    condition = alltrue([for c in values(var.connections) :
      contains(["aws", "azure", "gcp", "ibm"], c.cloud) && c.bandwidth_mbps > 0 &&
      c.vlan_tag >= 2 && c.vlan_tag <= 4092 && can(regex("^[A-Z]{2}$", c.metro_code))
    ])
    error_message = "cloud must be aws/azure/gcp/ibm, bandwidth > 0, VLAN 2-4092, metro a two-letter code."
  }
  validation {
    condition = alltrue([for c in values(var.connections) :
    c.cloud != "gcp" || !c.redundant || c.secondary_authentication_key != null])
    error_message = "GCP Partner Interconnect needs a second pairing key (availability domain 2) for the secondary leg."
  }
}
