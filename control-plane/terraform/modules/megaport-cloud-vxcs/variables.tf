variable "name_prefix" {
  description = "Prefix for VXC product names."
  type        = string
}

variable "cost_centre" {
  description = "Billing reference shown on Megaport invoices."
  type        = string
  default     = null
}

variable "resource_tags" {
  description = "Megaport resource tags (keys lowercase)."
  type        = map(string)
  default     = {}
}

variable "vxcs" {
  description = <<-EOT
    VXCs by key (e.g. aws-primary, aws-secondary). cloud is aws, azure, gcp or ibm.
    Create two per cloud on different A-End ports and diversity zones (red/blue) for redundancy;
    for Azure use port_choice primary and secondary with the same service key.
  EOT
  type = map(object({
    cloud                    = string
    a_end_product_uid        = string
    a_end_vlan               = optional(number, 0)
    rate_limit_mbps          = number
    contract_term_months     = optional(number, 1)
    partner_location_id      = optional(number)
    diversity_zone           = optional(string)
    aws_partner_product_name = optional(string)
    aws_account_id           = optional(string)
    azure_service_key        = optional(string)
    azure_port_choice        = optional(string, "primary")
    gcp_pairing_key          = optional(string)
    ibm_account_id           = optional(string)
    ibm_customer_asn         = optional(number)
  }))
  validation {
    condition = alltrue([for v in values(var.vxcs) :
      contains(["aws", "azure", "gcp", "ibm"], v.cloud) && v.rate_limit_mbps > 0 &&
    contains([1, 12, 24, 36, 48, 60], v.contract_term_months)])
    error_message = "cloud must be aws/azure/gcp/ibm, rate limit > 0, contract term 1/12/24/36/48/60."
  }
  validation {
    condition = alltrue([for v in values(var.vxcs) : (
      v.cloud == "aws" ? (v.aws_account_id != null && v.aws_partner_product_name != null && v.partner_location_id != null) :
      v.cloud == "azure" ? (v.azure_service_key != null && contains(["primary", "secondary"], v.azure_port_choice)) :
      v.cloud == "gcp" ? (v.gcp_pairing_key != null && v.partner_location_id != null) :
      (v.ibm_account_id != null && v.partner_location_id != null)
    )])
    error_message = "aws needs aws_account_id, aws_partner_product_name, partner_location_id; azure needs azure_service_key; gcp needs gcp_pairing_key and partner_location_id; ibm needs ibm_account_id and partner_location_id."
  }
}
