# Megaport VXCs from existing Megaport ports (or an MCR) to the cloud on-ramps: AWS Direct
# Connect hosted connections (AWSHC), Azure ExpressRoute (service key), Google Cloud Partner
# Interconnect (pairing key) and IBM Cloud Direct Link (account id). The schema follows the
# provider's own documentation at v1.26.3 (attribute syntax, b_end_partner_config).
#
# The provider never sends a changed cloud partner configuration on update: changing one fails
# the apply, so a change means replacing the VXC (plan it in a maintenance window).
# Provider credentials: MEGAPORT_ACCESS_KEY / MEGAPORT_SECRET_KEY (Vault: secret/data/coc/megaport).

data "megaport_partner" "aws" {
  for_each = { for k, v in var.vxcs : k => v if v.cloud == "aws" }

  connect_type   = "AWSHC"
  company_name   = "AWS"
  product_name   = each.value.aws_partner_product_name
  location_id    = each.value.partner_location_id
  diversity_zone = each.value.diversity_zone
}

data "megaport_partner" "gcp" {
  for_each = { for k, v in var.vxcs : k => v if v.cloud == "gcp" }

  connect_type   = "GOOGLE"
  company_name   = "Google"
  location_id    = each.value.partner_location_id
  diversity_zone = each.value.diversity_zone
}

data "megaport_partner" "ibm" {
  for_each = { for k, v in var.vxcs : k => v if v.cloud == "ibm" }

  connect_type   = "IBM"
  company_name   = "IBM"
  location_id    = each.value.partner_location_id
  diversity_zone = each.value.diversity_zone
}

resource "megaport_vxc" "this" {
  for_each = var.vxcs

  product_name         = "${var.name_prefix}-${each.key}"
  rate_limit           = each.value.rate_limit_mbps
  contract_term_months = each.value.contract_term_months
  cost_centre          = var.cost_centre
  resource_tags        = var.resource_tags

  a_end = {
    requested_product_uid = each.value.a_end_product_uid
    ordered_vlan          = each.value.a_end_vlan
  }

  # Azure picks the ExpressRoute port from the service key, so Azure has no requested B-End UID.
  b_end = {
    requested_product_uid = (
      each.value.cloud == "aws" ? data.megaport_partner.aws[each.key].product_uid :
      each.value.cloud == "gcp" ? data.megaport_partner.gcp[each.key].product_uid :
      each.value.cloud == "ibm" ? data.megaport_partner.ibm[each.key].product_uid : null
    )
  }

  b_end_partner_config = {
    partner = each.value.cloud == "gcp" ? "google" : each.value.cloud
    aws_config = each.value.cloud != "aws" ? null : {
      name          = "${var.name_prefix}-${each.key}"
      connect_type  = "AWSHC"
      owner_account = each.value.aws_account_id
    }
    azure_config = each.value.cloud != "azure" ? null : {
      port_choice = each.value.azure_port_choice
      service_key = each.value.azure_service_key
    }
    google_config = each.value.cloud != "gcp" ? null : {
      pairing_key = each.value.gcp_pairing_key
    }
    ibm_config = each.value.cloud != "ibm" ? null : {
      account_id   = each.value.ibm_account_id
      customer_asn = each.value.ibm_customer_asn
      name         = "${var.name_prefix}-${each.key}"
    }
  }
}
