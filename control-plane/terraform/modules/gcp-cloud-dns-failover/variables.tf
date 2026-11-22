variable "project" {
  description = "GCP project"
  type        = string
}

variable "managed_zone" {
  description = "Cloud DNS managed zone name (public zone)"
  type        = string
}

variable "record_name" {
  description = "Record name with trailing dot, e.g. app.example.com."
  type        = string
}

variable "ttl" {
  description = "TTL in seconds"
  type        = number
  default     = 30
}

variable "primary_ips" {
  description = "External IP addresses of the primary (production) endpoint"
  type        = list(string)
}

variable "backup_ips" {
  description = "External IP addresses of the backup (DR) endpoint"
  type        = list(string)
}

variable "backup_location" {
  description = "Cloud region that answers with the backup when the primary is unhealthy"
  type        = string
}

variable "health_check" {
  description = "HTTPS health check of the endpoints"
  type = object({
    port         = optional(number, 443)
    request_path = optional(string, "/healthz")
    host         = optional(string)
  })
  default = {}
}

variable "health_check_source_regions" {
  description = "Three regions Cloud DNS health checks probe from"
  type        = list(string)
}
