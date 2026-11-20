output "profile_fqdn" {
  description = "Traffic Manager host name"
  value       = azurerm_traffic_manager_profile.this.fqdn
}

output "profile_id" {
  description = "Traffic Manager profile id"
  value       = azurerm_traffic_manager_profile.this.id
}
