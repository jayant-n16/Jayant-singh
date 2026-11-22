output "dx_gateway_id" {
  value = aws_dx_gateway.this.id
}

output "virtual_interface_ids" {
  value = { for k, v in aws_dx_private_virtual_interface.this : k => v.id }
}
