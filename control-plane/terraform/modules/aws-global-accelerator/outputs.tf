output "accelerator_arn" {
  value = aws_globalaccelerator_accelerator.this.arn
}

output "dns_name" {
  description = "Point the global hostname (CNAME/ALIAS) here."
  value       = aws_globalaccelerator_accelerator.this.dns_name
}

output "dual_stack_dns_name" {
  value = aws_globalaccelerator_accelerator.this.dual_stack_dns_name
}

output "static_ips" {
  description = "Anycast static IP addresses."
  value       = flatten([for s in aws_globalaccelerator_accelerator.this.ip_sets : s.ip_addresses])
}

output "endpoint_group_arns" {
  description = "Endpoint group ARN by key - put these in OPLIA_NETWORK_ENDPOINT_GROUPS."
  value       = { for k, g in aws_globalaccelerator_endpoint_group.this : k => g.arn }
}
