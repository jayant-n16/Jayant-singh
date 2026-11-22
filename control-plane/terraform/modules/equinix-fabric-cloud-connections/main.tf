# Equinix Fabric virtual connections (EVPL_VC) from an Equinix port to the cloud on-ramps:
# AWS Direct Connect (hosted connection), Azure ExpressRoute, Google Cloud Partner Interconnect
# and IBM Cloud Direct Link 2.0 (Connect). Each connection has a PRIMARY and, unless disabled, a
# SECONDARY in the same redundancy group (on the secondary port), because every cloud's SLA for
# these products assumes two diverse paths.
#
# Authentication keys by cloud (Equinix "authentication_key"):
#   aws   - the AWS account id that accepts the hosted connection (modules/aws-dx-hosted-accept)
#   azure - the ExpressRoute circuit service key (modules/azure-expressroute-circuit output)
#   gcp   - the pairing key of each Partner attachment (modules/gcp-partner-interconnect output);
#           primary and secondary use different keys (availability domains 1 and 2)
#   ibm   - the IBM Cloud account id; the gateway is then approved on the IBM side
#           (modules/ibm-direct-link-approve)
#
# Service profile UUIDs differ per metro and change rarely; look them up once in the Fabric
# portal or API ("AWS Direct Connect", "Azure ExpressRoute", "Google Cloud Partner Interconnect
# Zone 1/2", "IBM Cloud Direct Link 2") and pass them in. Credentials for the provider come from
# EQUINIX_API_CLIENTID / EQUINIX_API_CLIENTSECRET (Vault: secret/data/coc/equinix), never here.

locals {
  # One entry per physical leg; secondary legs exist only where redundant = true.
  legs = merge(
    { for k, c in var.connections : "${k}-primary" => merge(c, {
      key  = k, priority = "PRIMARY", port_uuid = var.primary_port_uuid,
      auth = c.authentication_key, profile = c.service_profile_uuid, vlan = c.vlan_tag
    }) },
    { for k, c in var.connections : "${k}-secondary" => merge(c, {
      key     = k, priority = "SECONDARY", port_uuid = var.secondary_port_uuid,
      auth    = coalesce(c.secondary_authentication_key, c.authentication_key),
      profile = coalesce(c.secondary_service_profile_uuid, c.service_profile_uuid),
      vlan    = coalesce(c.secondary_vlan_tag, c.vlan_tag)
    }) if c.redundant },
  )
}

resource "equinix_fabric_connection" "primary" {
  for_each = { for k, l in local.legs : k => l if l.priority == "PRIMARY" }

  name      = "${var.name_prefix}-${each.value.key}-pri"
  type      = "EVPL_VC"
  bandwidth = each.value.bandwidth_mbps

  notifications {
    type   = "ALL"
    emails = var.notification_emails
  }

  redundancy {
    priority = "PRIMARY"
  }

  order {
    purchase_order_number = var.purchase_order_number
  }

  a_side {
    access_point {
      type = "COLO"
      port {
        uuid = each.value.port_uuid
      }
      link_protocol {
        type     = "DOT1Q"
        vlan_tag = each.value.vlan
      }
    }
  }

  z_side {
    access_point {
      type               = "SP"
      authentication_key = each.value.auth
      seller_region      = each.value.seller_region
      peering_type       = each.value.cloud == "azure" ? "PRIVATE" : null
      profile {
        type = "L2_PROFILE"
        uuid = each.value.profile
      }
      location {
        metro_code = each.value.metro_code
      }
    }
  }
}

resource "equinix_fabric_connection" "secondary" {
  for_each = { for k, l in local.legs : k => l if l.priority == "SECONDARY" }

  name      = "${var.name_prefix}-${each.value.key}-sec"
  type      = "EVPL_VC"
  bandwidth = each.value.bandwidth_mbps

  notifications {
    type   = "ALL"
    emails = var.notification_emails
  }

  redundancy {
    priority = "SECONDARY"
    group    = one(equinix_fabric_connection.primary["${each.value.key}-primary"].redundancy).group
  }

  order {
    purchase_order_number = var.purchase_order_number
  }

  a_side {
    access_point {
      type = "COLO"
      port {
        uuid = each.value.port_uuid
      }
      link_protocol {
        type     = "DOT1Q"
        vlan_tag = each.value.vlan
      }
    }
  }

  z_side {
    access_point {
      type               = "SP"
      authentication_key = each.value.auth
      seller_region      = each.value.seller_region
      peering_type       = each.value.cloud == "azure" ? "PRIVATE" : null
      profile {
        type = "L2_PROFILE"
        uuid = each.value.profile
      }
      location {
        metro_code = each.value.metro_code
      }
    }
  }
}
