# Cloud DNS primary/backup routing with health-checked external endpoints: answers with the primary
# IPs while they are healthy, otherwise with the backup IPs. Failover is automatic; OPLIA reads the
# state but does not offer a forced switch for Cloud DNS.

resource "google_compute_health_check" "this" {
  project             = var.project
  name                = "oplia-dns-failover-${replace(trimsuffix(var.record_name, "."), ".", "-")}"
  check_interval_sec  = 30
  timeout_sec         = 10
  healthy_threshold   = 2
  unhealthy_threshold = 3
  source_regions      = var.health_check_source_regions

  https_health_check {
    port         = var.health_check.port
    request_path = var.health_check.request_path
    host         = var.health_check.host
  }
}

resource "google_dns_record_set" "this" {
  project      = var.project
  managed_zone = var.managed_zone
  name         = var.record_name
  type         = "A"
  ttl          = var.ttl

  routing_policy {
    health_check = google_compute_health_check.this.id

    primary_backup {
      trickle_ratio = 0

      primary {
        external_endpoints = var.primary_ips
      }

      backup_geo {
        location = var.backup_location
        health_checked_targets {
          external_endpoints = var.backup_ips
        }
      }
    }
  }
}
