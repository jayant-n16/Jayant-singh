output "health_check_id" {
  description = "Health check used by the record set"
  value       = google_compute_health_check.this.id
}
