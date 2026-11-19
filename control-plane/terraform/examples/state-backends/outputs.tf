output "aws_backend_config" {
  description = "S3 backend settings for the pipelines."
  value       = module.aws_state.backend_config
}

output "azure_backend_config" {
  description = "azurerm backend settings for the pipelines."
  value       = module.azure_state.backend_config
}
