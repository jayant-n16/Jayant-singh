variable "name" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

variable "service_provider_name" {
  description = "\"Equinix\" or \"Megaport\" (as listed by az network express-route list-service-providers)."
  type        = string
  validation {
    condition     = contains(["Equinix", "Megaport"], var.service_provider_name)
    error_message = "service_provider_name must be Equinix or Megaport."
  }
}

variable "peering_location" {
  description = "ExpressRoute peering location offered by the provider, e.g. \"Silicon Valley\"."
  type        = string
}

variable "bandwidth_in_mbps" {
  type = number
}

variable "sku_tier" {
  type    = string
  default = "Standard"
  validation {
    condition     = contains(["Local", "Standard", "Premium"], var.sku_tier)
    error_message = "sku_tier must be Local, Standard or Premium."
  }
}

variable "sku_family" {
  type    = string
  default = "MeteredData"
  validation {
    condition     = contains(["MeteredData", "UnlimitedData"], var.sku_family)
    error_message = "sku_family must be MeteredData or UnlimitedData."
  }
}

variable "private_peering" {
  description = "Set after the provider has provisioned the circuit (second apply)."
  type = object({
    peer_asn                      = number
    primary_peer_address_prefix   = string
    secondary_peer_address_prefix = string
    vlan_id                       = number
    shared_key                    = optional(string)
  })
  default = null
}

variable "tags" {
  type    = map(string)
  default = {}
}
