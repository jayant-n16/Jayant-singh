# Azure side: an ExpressRoute circuit whose service key is handed to Equinix Fabric or Megaport,
# and (second apply, after the provider shows "Provisioned") the private peering.

resource "azurerm_express_route_circuit" "this" {
  name                     = var.name
  resource_group_name      = var.resource_group_name
  location                 = var.location
  service_provider_name    = var.service_provider_name
  peering_location         = var.peering_location
  bandwidth_in_mbps        = var.bandwidth_in_mbps
  allow_classic_operations = false

  sku {
    tier   = var.sku_tier
    family = var.sku_family
  }

  tags = var.tags
}

resource "azurerm_express_route_circuit_peering" "private" {
  count = var.private_peering == null ? 0 : 1

  peering_type                  = "AzurePrivatePeering"
  express_route_circuit_name    = azurerm_express_route_circuit.this.name
  resource_group_name           = var.resource_group_name
  peer_asn                      = var.private_peering.peer_asn
  primary_peer_address_prefix   = var.private_peering.primary_peer_address_prefix
  secondary_peer_address_prefix = var.private_peering.secondary_peer_address_prefix
  vlan_id                       = var.private_peering.vlan_id
  shared_key                    = var.private_peering.shared_key
}
