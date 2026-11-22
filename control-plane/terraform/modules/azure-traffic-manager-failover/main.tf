# Azure DNS has no health-checked failover of its own; Traffic Manager priority routing provides it.
# OPLIA's dr.dns_failover job forces a failover by disabling the primary endpoint and fails back
# by enabling it again.

resource "azurerm_traffic_manager_profile" "this" {
  name                   = var.profile_name
  resource_group_name    = var.resource_group_name
  traffic_routing_method = "Priority"
  tags                   = var.tags

  dns_config {
    relative_name = coalesce(var.dns_label, var.profile_name)
    ttl           = var.ttl
  }

  monitor_config {
    protocol                     = var.monitor.protocol
    port                         = var.monitor.port
    path                         = var.monitor.path
    interval_in_seconds          = var.monitor.interval_in_seconds
    timeout_in_seconds           = var.monitor.timeout_in_seconds
    tolerated_number_of_failures = var.monitor.tolerated_number_of_failures
  }
}

resource "azurerm_traffic_manager_external_endpoint" "primary" {
  name       = "primary"
  profile_id = azurerm_traffic_manager_profile.this.id
  target     = var.primary_target
  priority   = 1
  enabled    = true

  lifecycle {
    ignore_changes = [enabled] # flipped by the gated OPLIA failover job
  }
}

resource "azurerm_traffic_manager_external_endpoint" "secondary" {
  name       = "secondary"
  profile_id = azurerm_traffic_manager_profile.this.id
  target     = var.secondary_target
  priority   = 2
}

resource "azurerm_dns_cname_record" "this" {
  count               = var.dns_zone == null ? 0 : 1
  name                = var.dns_zone.record_name
  zone_name           = var.dns_zone.name
  resource_group_name = var.dns_zone.resource_group_name
  ttl                 = var.ttl
  target_resource_id  = azurerm_traffic_manager_profile.this.id
}
