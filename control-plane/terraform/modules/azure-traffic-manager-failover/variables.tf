variable "resource_group_name" {
  description = "Resource group for the Traffic Manager profile"
  type        = string
}

variable "profile_name" {
  description = "Traffic Manager profile name (also the trafficmanager.net DNS label unless dns_label is set)"
  type        = string
}

variable "dns_label" {
  description = "Relative DNS name under trafficmanager.net"
  type        = string
  default     = null
}

variable "ttl" {
  description = "DNS TTL in seconds"
  type        = number
  default     = 30
}

variable "monitor" {
  description = "Endpoint monitoring"
  type = object({
    protocol                     = optional(string, "HTTPS")
    port                         = optional(number, 443)
    path                         = optional(string, "/healthz")
    interval_in_seconds          = optional(number, 30)
    timeout_in_seconds           = optional(number, 10)
    tolerated_number_of_failures = optional(number, 3)
  })
  default = {}
}

variable "primary_target" {
  description = "Host name of the primary (production) endpoint"
  type        = string
}

variable "secondary_target" {
  description = "Host name of the secondary (DR) endpoint"
  type        = string
}

variable "dns_zone" {
  description = "Optional Azure DNS zone to publish a CNAME to the profile in"
  type = object({
    name                = string
    resource_group_name = string
    record_name         = string
  })
  default = null
}

variable "tags" {
  description = "Tags"
  type        = map(string)
  default     = {}
}
