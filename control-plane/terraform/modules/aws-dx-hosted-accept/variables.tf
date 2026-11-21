variable "name" {
  description = "Name of the Direct Connect gateway and prefix for virtual interfaces."
  type        = string
}

variable "amazon_side_asn" {
  description = "Amazon-side private ASN of the Direct Connect gateway."
  type        = string
  default     = "64512"
}

variable "customer_bgp_asn" {
  description = "Your BGP ASN on the partner side (Equinix/Megaport router or your edge)."
  type        = number
}

variable "jumbo_frames" {
  description = "Use MTU 8500 on the virtual interfaces."
  type        = bool
  default     = false
}

variable "hosted_connections" {
  description = "Hosted connections by key (e.g. equinix-primary). vlan is the VLAN the partner assigned."
  type = map(object({
    connection_id    = string
    vlan             = number
    bgp_auth_key     = optional(string)
    amazon_address   = optional(string)
    customer_address = optional(string)
  }))
  default = {}
  validation {
    condition     = alltrue([for c in values(var.hosted_connections) : can(regex("^dxcon-[a-z0-9]+$", c.connection_id)) && c.vlan >= 1 && c.vlan <= 4094])
    error_message = "connection_id must look like dxcon-xxxx and vlan be 1-4094."
  }
}

variable "associated_gateways" {
  description = "Transit gateways or virtual private gateways to associate with the DX gateway."
  type = map(object({
    gateway_id       = string
    allowed_prefixes = optional(list(string))
  }))
  default = {}
}

variable "tags" {
  type    = map(string)
  default = {}
}
