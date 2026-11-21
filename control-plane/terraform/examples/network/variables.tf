variable "aws_region" { type = string }
variable "aws_account_id" { type = string }
variable "aws_alb_arn" { type = string }
variable "flow_logs_bucket" { type = string }
variable "azure_forwarder_region" { type = string }
variable "azure_forwarder_nlb_arn" { type = string }
variable "gcp_forwarder_region" { type = string }
variable "gcp_forwarder_nlb_arn" { type = string }
variable "ibm_forwarder_region" { type = string }
variable "ibm_forwarder_nlb_arn" { type = string }
variable "azure_resource_group" { type = string }
variable "azure_location" { type = string }
variable "azure_peering_location" { type = string }
variable "gcp_project" { type = string }
variable "gcp_region" { type = string }
variable "gcp_network" { type = string }
variable "ibm_region" { type = string }
variable "ibm_account_id" { type = string }
variable "ibm_resource_group_id" { type = string }
variable "customer_bgp_asn" { type = number }
variable "notification_emails" { type = list(string) }
variable "equinix_metro" { type = string }
variable "equinix_primary_port_uuid" { type = string }
variable "equinix_secondary_port_uuid" { type = string }
variable "equinix_profiles" {
  type = object({ aws = string, azure = string, gcp_zone1 = string, gcp_zone2 = string, ibm = string })
}
variable "megaport_port_uids" {
  type = list(string)
  validation {
    condition     = length(var.megaport_port_uids) == 2
    error_message = "Two Megaport ports (one per diversity zone) are required."
  }
}
variable "megaport_aws_location_id" { type = number }
variable "megaport_aws_product_name" { type = string }
variable "megaport_gcp_location_id" { type = number }
variable "megaport_ibm_location_id" { type = number }
variable "aws_hosted_connections" {
  type = map(object({
    connection_id    = string
    vlan             = number
    bgp_auth_key     = optional(string)
    amazon_address   = optional(string)
    customer_address = optional(string)
  }))
  default = {}
}
variable "ibm_pending_gateways" {
  type = map(object({
    name                        = string
    global                      = optional(bool, false)
    metered                     = optional(bool, false)
    connection_mode             = optional(string, "transit")
    default_import_route_filter = optional(string, "permit")
  }))
  default = {}
}
