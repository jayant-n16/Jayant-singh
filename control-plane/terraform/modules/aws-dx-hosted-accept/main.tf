# AWS side of a partner (Equinix Fabric or Megaport) hosted connection: accept the hosted
# connections the partner created in this account, then attach a private virtual interface on
# each to a Direct Connect gateway. The connection ids exist only after the partner order, so
# this is the second apply of the two-step order (partner first, then this module).

resource "aws_dx_gateway" "this" {
  name            = var.name
  amazon_side_asn = var.amazon_side_asn
}

resource "aws_dx_connection_confirmation" "this" {
  for_each      = var.hosted_connections
  connection_id = each.value.connection_id
}

resource "aws_dx_private_virtual_interface" "this" {
  for_each = var.hosted_connections

  connection_id    = aws_dx_connection_confirmation.this[each.key].connection_id
  name             = "${var.name}-${each.key}"
  vlan             = each.value.vlan
  address_family   = "ipv4"
  bgp_asn          = var.customer_bgp_asn
  bgp_auth_key     = each.value.bgp_auth_key
  amazon_address   = each.value.amazon_address
  customer_address = each.value.customer_address
  dx_gateway_id    = aws_dx_gateway.this.id
  mtu              = var.jumbo_frames ? 8500 : 1500
  tags             = var.tags
}

resource "aws_dx_gateway_association" "this" {
  for_each = var.associated_gateways

  dx_gateway_id         = aws_dx_gateway.this.id
  associated_gateway_id = each.value.gateway_id
  allowed_prefixes      = each.value.allowed_prefixes
}
