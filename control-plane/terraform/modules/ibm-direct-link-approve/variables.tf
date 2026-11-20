variable "resource_group_id" {
  type = string
}

variable "gateways" {
  description = "Pending provider-created gateways by key, with the name the partner gave them."
  type = map(object({
    name                        = string
    global                      = optional(bool, false)
    metered                     = optional(bool, false)
    connection_mode             = optional(string, "transit")
    default_import_route_filter = optional(string, "permit")
  }))
  validation {
    condition = alltrue([for g in values(var.gateways) :
    contains(["direct", "transit"], g.connection_mode) && contains(["permit", "deny"], g.default_import_route_filter)])
    error_message = "connection_mode must be direct or transit; default_import_route_filter permit or deny."
  }
}
