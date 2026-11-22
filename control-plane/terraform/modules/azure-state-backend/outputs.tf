output "storage_account_name" {
  description = "OPLIA_AZURE_STATE_ACCOUNT."
  value       = azurerm_storage_account.state.name
}

output "container_name" {
  description = "OPLIA_AZURE_STATE_CONTAINER."
  value       = azurerm_storage_container.state.name
}

output "resource_group_name" {
  description = "OPLIA_AZURE_STATE_RG."
  value       = local.resource_group_name
}

output "backend_config" {
  description = "Values for `terraform init -backend-config=...` with an empty `backend \"azurerm\" {}` block."
  value = {
    resource_group_name  = local.resource_group_name
    storage_account_name = azurerm_storage_account.state.name
    container_name       = azurerm_storage_container.state.name
    use_azuread_auth     = true
  }
}
