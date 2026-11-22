output "gateway_ids" {
  value = { for k, g in data.ibm_dl_gateway.this : k => g.id }
}
