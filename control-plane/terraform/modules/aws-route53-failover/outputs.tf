output "primary_health_check_id" {
  description = "Health check id OPLIA inverts to force a failover (dns failover setting primary_health_check_id)"
  value       = aws_route53_health_check.this["primary"].id
}

output "secondary_health_check_id" {
  description = "Health check id of the DR endpoint"
  value       = aws_route53_health_check.this["secondary"].id
}
