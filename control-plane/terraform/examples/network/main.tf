# Example: global entry (AWS Global Accelerator) plus redundant private interconnects to all four
# clouds through Equinix Fabric AND Megaport. Validated with `terraform validate` in CI only;
# never applied - every id below is a placeholder variable. Real order of operations:
#   1. apply cloud sides that mint keys (Azure circuit, GCP attachments);
#   2. apply the partner connections (Equinix and/or Megaport) with those keys;
#   3. apply the accepting sides (AWS hosted connection accept, IBM approve, Azure peering,
#      GCP activate) once the partner reports the connections provisioned.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws      = { source = "hashicorp/aws", version = "6.72.0" }
    azurerm  = { source = "hashicorp/azurerm", version = "5.13.0" }
    google   = { source = "hashicorp/google", version = "8.10.0" }
    ibm      = { source = "IBM-Cloud/ibm", version = "2.9.0" }
    equinix  = { source = "equinix/equinix", version = "5.3.0" }
    megaport = { source = "megaport/megaport", version = "1.26.3" }
  }
}

# Global Accelerator's API lives in us-west-2 regardless of where the endpoints are.
provider "aws" {
  alias  = "ga"
  region = "us-west-2"
}

provider "aws" {
  region = var.aws_region
}

provider "azurerm" {
  features {}
}

provider "google" {
  project = var.gcp_project
}

provider "ibm" {
  region = var.ibm_region
}

provider "equinix" {}

provider "megaport" {
  environment           = "production"
  accept_purchase_terms = true
}

module "global_accelerator" {
  source    = "../../modules/aws-global-accelerator"
  providers = { aws = aws.ga }

  name                = "oplia-global"
  flow_logs_s3_bucket = var.flow_logs_bucket
  listeners = {
    https = { port_ranges = [{ from_port = 443, to_port = 443 }] }
  }
  # Every cloud is one endpoint group; non-AWS clouds through an NLB that forwards over the
  # interconnect. Start at 100 for the current primary and 0 for the others; OPLIA moves them.
  endpoint_groups = {
    aws   = { listener = "https", region = var.aws_region, initial_traffic_dial = 100, endpoints = [{ endpoint_id = var.aws_alb_arn }] }
    azure = { listener = "https", region = var.azure_forwarder_region, endpoints = [{ endpoint_id = var.azure_forwarder_nlb_arn, client_ip_preservation_enabled = false }] }
    gcp   = { listener = "https", region = var.gcp_forwarder_region, endpoints = [{ endpoint_id = var.gcp_forwarder_nlb_arn, client_ip_preservation_enabled = false }] }
    ibm   = { listener = "https", region = var.ibm_forwarder_region, endpoints = [{ endpoint_id = var.ibm_forwarder_nlb_arn, client_ip_preservation_enabled = false }] }
  }
}

module "azure_er_equinix" {
  source                = "../../modules/azure-expressroute-circuit"
  name                  = "oplia-er-equinix"
  resource_group_name   = var.azure_resource_group
  location              = var.azure_location
  service_provider_name = "Equinix"
  peering_location      = var.azure_peering_location
  bandwidth_in_mbps     = 1000
}

module "azure_er_megaport" {
  source                = "../../modules/azure-expressroute-circuit"
  name                  = "oplia-er-megaport"
  resource_group_name   = var.azure_resource_group
  location              = var.azure_location
  service_provider_name = "Megaport"
  peering_location      = var.azure_peering_location
  bandwidth_in_mbps     = 1000
}

module "gcp_equinix" {
  source  = "../../modules/gcp-partner-interconnect"
  name    = "oplia-pi-equinix"
  project = var.gcp_project
  region  = var.gcp_region
  network = var.gcp_network
}

module "gcp_megaport" {
  source  = "../../modules/gcp-partner-interconnect"
  name    = "oplia-pi-megaport"
  project = var.gcp_project
  region  = var.gcp_region
  network = var.gcp_network
}

module "equinix" {
  source              = "../../modules/equinix-fabric-cloud-connections"
  name_prefix         = "oplia"
  primary_port_uuid   = var.equinix_primary_port_uuid
  secondary_port_uuid = var.equinix_secondary_port_uuid
  notification_emails = var.notification_emails
  connections = {
    aws = {
      cloud                = "aws", bandwidth_mbps = 1000, metro_code = var.equinix_metro, seller_region = var.aws_region,
      service_profile_uuid = var.equinix_profiles.aws, authentication_key = var.aws_account_id, vlan_tag = 101
    }
    azure = {
      cloud                = "azure", bandwidth_mbps = 1000, metro_code = var.equinix_metro,
      service_profile_uuid = var.equinix_profiles.azure, authentication_key = module.azure_er_equinix.service_key, vlan_tag = 102
    }
    gcp = {
      cloud                          = "gcp", bandwidth_mbps = 1000, metro_code = var.equinix_metro, seller_region = var.gcp_region,
      service_profile_uuid           = var.equinix_profiles.gcp_zone1, authentication_key = module.gcp_equinix.pairing_keys["1"],
      secondary_service_profile_uuid = var.equinix_profiles.gcp_zone2, secondary_authentication_key = module.gcp_equinix.pairing_keys["2"],
      vlan_tag                       = 103
    }
    ibm = {
      cloud                = "ibm", bandwidth_mbps = 1000, metro_code = var.equinix_metro, seller_region = var.ibm_region,
      service_profile_uuid = var.equinix_profiles.ibm, authentication_key = var.ibm_account_id, vlan_tag = 104
    }
  }
}

module "megaport" {
  source      = "../../modules/megaport-cloud-vxcs"
  name_prefix = "oplia"
  vxcs = {
    aws-primary     = { cloud = "aws", a_end_product_uid = var.megaport_port_uids[0], rate_limit_mbps = 1000, partner_location_id = var.megaport_aws_location_id, diversity_zone = "red", aws_partner_product_name = var.megaport_aws_product_name, aws_account_id = var.aws_account_id }
    aws-secondary   = { cloud = "aws", a_end_product_uid = var.megaport_port_uids[1], rate_limit_mbps = 1000, partner_location_id = var.megaport_aws_location_id, diversity_zone = "blue", aws_partner_product_name = var.megaport_aws_product_name, aws_account_id = var.aws_account_id }
    azure-primary   = { cloud = "azure", a_end_product_uid = var.megaport_port_uids[0], rate_limit_mbps = 1000, azure_service_key = module.azure_er_megaport.service_key, azure_port_choice = "primary" }
    azure-secondary = { cloud = "azure", a_end_product_uid = var.megaport_port_uids[1], rate_limit_mbps = 1000, azure_service_key = module.azure_er_megaport.service_key, azure_port_choice = "secondary" }
    gcp-primary     = { cloud = "gcp", a_end_product_uid = var.megaport_port_uids[0], rate_limit_mbps = 1000, partner_location_id = var.megaport_gcp_location_id, diversity_zone = "red", gcp_pairing_key = module.gcp_megaport.pairing_keys["1"] }
    gcp-secondary   = { cloud = "gcp", a_end_product_uid = var.megaport_port_uids[1], rate_limit_mbps = 1000, partner_location_id = var.megaport_gcp_location_id, diversity_zone = "blue", gcp_pairing_key = module.gcp_megaport.pairing_keys["2"] }
    ibm-primary     = { cloud = "ibm", a_end_product_uid = var.megaport_port_uids[0], rate_limit_mbps = 1000, partner_location_id = var.megaport_ibm_location_id, diversity_zone = "red", ibm_account_id = var.ibm_account_id, ibm_customer_asn = var.customer_bgp_asn }
    ibm-secondary   = { cloud = "ibm", a_end_product_uid = var.megaport_port_uids[1], rate_limit_mbps = 1000, partner_location_id = var.megaport_ibm_location_id, diversity_zone = "blue", ibm_account_id = var.ibm_account_id, ibm_customer_asn = var.customer_bgp_asn }
  }
}

# Step 3 (after the partners report the connections provisioned).
module "aws_accept" {
  source             = "../../modules/aws-dx-hosted-accept"
  name               = "oplia-dxgw"
  customer_bgp_asn   = var.customer_bgp_asn
  hosted_connections = var.aws_hosted_connections
}

module "ibm_approve" {
  source            = "../../modules/ibm-direct-link-approve"
  resource_group_id = var.ibm_resource_group_id
  gateways          = var.ibm_pending_gateways
}

output "global_dns_name" {
  value = module.global_accelerator.dns_name
}

output "endpoint_group_arns" {
  value = module.global_accelerator.endpoint_group_arns
}
