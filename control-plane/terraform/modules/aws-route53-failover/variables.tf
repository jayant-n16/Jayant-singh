variable "zone_id" {
  description = "Route 53 hosted zone id"
  type        = string
}

variable "record_name" {
  description = "Fully qualified record name, e.g. app.example.com"
  type        = string
}

variable "record_type" {
  description = "A for IP endpoints, CNAME for host name endpoints"
  type        = string
  default     = "CNAME"
  validation {
    condition     = contains(["A", "AAAA", "CNAME"], var.record_type)
    error_message = "record_type must be A, AAAA or CNAME."
  }
}

variable "ttl" {
  description = "Record TTL in seconds (keep low so failover takes effect quickly)"
  type        = number
  default     = 60
}

variable "primary" {
  description = "Primary endpoint (production cloud)"
  type = object({
    value         = string           # IP address or host name the record points to
    fqdn          = optional(string) # host name the health check calls (default: value)
    port          = optional(number, 443)
    resource_path = optional(string, "/healthz")
    type          = optional(string, "HTTPS")
  })
}

variable "secondary" {
  description = "Secondary endpoint (DR cloud)"
  type = object({
    value         = string
    fqdn          = optional(string)
    port          = optional(number, 443)
    resource_path = optional(string, "/healthz")
    type          = optional(string, "HTTPS")
  })
}

variable "failure_threshold" {
  description = "Consecutive failed checks before an endpoint is unhealthy"
  type        = number
  default     = 3
}

variable "tags" {
  description = "Tags for the health checks"
  type        = map(string)
  default     = {}
}
