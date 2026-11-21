# IBM side: Equinix Fabric or Megaport creates a Direct Link Connect gateway in this account
# (authentication key = IBM account id); it waits for the customer's approval. This module looks
# the pending gateway up by name and approves it (ibm_dl_gateway_action create_gateway_approve,
# per the provider documentation at v2.9.0).

data "ibm_dl_gateway" "this" {
  for_each = var.gateways
  name     = each.value.name
}

resource "ibm_dl_gateway_action" "approve" {
  for_each = var.gateways

  gateway                     = data.ibm_dl_gateway.this[each.key].id
  action                      = "create_gateway_approve"
  global                      = each.value.global
  metered                     = each.value.metered
  resource_group              = var.resource_group_id
  connection_mode             = each.value.connection_mode
  default_export_route_filter = "permit"
  default_import_route_filter = each.value.default_import_route_filter
}
