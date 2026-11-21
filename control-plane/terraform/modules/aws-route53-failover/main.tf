# Route 53 failover routing: PRIMARY answers while its health check passes, otherwise SECONDARY.
# OPLIA's dr.dns_failover job forces a failover by inverting the PRIMARY health check (and fails
# back by un-inverting it); nothing else in this module is changed at run time.

locals {
  endpoints = { primary = var.primary, secondary = var.secondary }
}

resource "aws_route53_health_check" "this" {
  for_each          = local.endpoints
  fqdn              = coalesce(each.value.fqdn, each.value.value)
  port              = each.value.port
  type              = each.value.type
  resource_path     = each.value.resource_path
  failure_threshold = var.failure_threshold
  request_interval  = 10
  measure_latency   = true
  tags              = merge(var.tags, { Name = "${var.record_name}-${each.key}", "oplia-dns-failover" = each.key })

  lifecycle {
    ignore_changes = [invert_healthcheck] # flipped by the gated OPLIA failover job
  }
}

resource "aws_route53_record" "this" {
  for_each        = local.endpoints
  zone_id         = var.zone_id
  name            = var.record_name
  type            = var.record_type
  ttl             = var.ttl
  records         = [each.value.value]
  set_identifier  = "${var.record_name}-${each.key}"
  health_check_id = aws_route53_health_check.this[each.key].id

  failover_routing_policy {
    type = upper(each.key)
  }
}
