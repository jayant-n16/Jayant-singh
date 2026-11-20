output "service_key" {
  description = "Give this to Equinix Fabric (authentication_key) or Megaport (azure_service_key)."
  value       = azurerm_express_route_circuit.this.service_key
  sensitive   = true
}

output "circuit_id" {
  value = azurerm_express_route_circuit.this.id
}

output "service_provider_provisioning_state" {
  value = azurerm_express_route_circuit.this.service_provider_provisioning_state
}
