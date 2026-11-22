variable "name" {
  description = "Accelerator name (1-64 characters: letters, digits, hyphens)."
  type        = string
  validation {
    condition     = can(regex("^[A-Za-z0-9-]{1,64}$", var.name))
    error_message = "name must be 1-64 letters, digits or hyphens."
  }
}

variable "ip_address_type" {
  description = "IPV4 or DUAL_STACK."
  type        = string
  default     = "IPV4"
  validation {
    condition     = contains(["IPV4", "DUAL_STACK"], var.ip_address_type)
    error_message = "ip_address_type must be IPV4 or DUAL_STACK."
  }
}

variable "enabled" {
  description = "Whether the accelerator accepts traffic."
  type        = bool
  default     = true
}

variable "flow_logs_s3_bucket" {
  description = "Existing S3 bucket for accelerator flow logs (flow logs are always on)."
  type        = string
  nullable    = false
}

variable "flow_logs_s3_prefix" {
  description = "Key prefix for flow logs."
  type        = string
  default     = "global-accelerator/"
}

variable "listeners" {
  description = "Listeners by key. protocol TCP or UDP; client_affinity NONE or SOURCE_IP."
  type = map(object({
    protocol        = optional(string, "TCP")
    client_affinity = optional(string, "NONE")
    port_ranges = list(object({
      from_port = number
      to_port   = number
    }))
  }))
  validation {
    condition = alltrue([for l in values(var.listeners) :
      contains(["TCP", "UDP"], l.protocol) && contains(["NONE", "SOURCE_IP"], l.client_affinity) && length(l.port_ranges) > 0 &&
    alltrue([for p in l.port_ranges : p.from_port >= 1 && p.to_port <= 65535 && p.from_port <= p.to_port])])
    error_message = "Each listener needs TCP/UDP, NONE/SOURCE_IP and at least one valid port range."
  }
}

variable "endpoint_groups" {
  description = <<-EOT
    Endpoint groups by key (use the cloud name, e.g. aws, azure, gcp, ibm - OPLIA shows this key).
    listener must be a key of var.listeners; region is the AWS region of the endpoints; endpoints
    are ALB/NLB/instance ARNs or EIP allocation ids. initial_traffic_dial applies at creation only.
  EOT
  type = map(object({
    listener                      = string
    region                        = string
    initial_traffic_dial          = optional(number, 0)
    health_check_protocol         = optional(string, "HTTPS")
    health_check_port             = optional(number, 443)
    health_check_path             = optional(string, "/healthz")
    health_check_interval_seconds = optional(number, 10)
    threshold_count               = optional(number, 3)
    endpoints = list(object({
      endpoint_id                    = string
      weight                         = optional(number, 128)
      client_ip_preservation_enabled = optional(bool, true)
    }))
  }))
  validation {
    condition = alltrue([for g in values(var.endpoint_groups) :
      g.initial_traffic_dial >= 0 && g.initial_traffic_dial <= 100 &&
      contains(["TCP", "HTTP", "HTTPS"], g.health_check_protocol) &&
      contains([10, 30], g.health_check_interval_seconds) &&
      g.threshold_count >= 1 && g.threshold_count <= 10 && length(g.endpoints) > 0 &&
    alltrue([for e in g.endpoints : e.weight >= 0 && e.weight <= 255])])
    error_message = "traffic dial 0-100, health check TCP/HTTP/HTTPS every 10 or 30 s, threshold 1-10, weights 0-255, at least one endpoint."
  }
}

variable "tags" {
  description = "Tags for the accelerator."
  type        = map(string)
  default     = {}
}
