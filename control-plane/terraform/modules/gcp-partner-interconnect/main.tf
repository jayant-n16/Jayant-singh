# GCP side: a Cloud Router (ASN 16550 is mandatory for Partner Interconnect) and two PARTNER
# VLAN attachments in availability domains 1 and 2. Their pairing keys go to Equinix Fabric or
# Megaport; after the partner provisions them, activate the attachments (admin_enabled).

resource "google_compute_router" "this" {
  name    = var.name
  project = var.project
  region  = var.region
  network = var.network

  bgp {
    asn = 16550
  }
}

resource "google_compute_interconnect_attachment" "this" {
  for_each = toset(var.availability_domains)

  name                     = "${var.name}-ad${each.value}"
  project                  = var.project
  region                   = var.region
  router                   = google_compute_router.this.id
  type                     = "PARTNER"
  edge_availability_domain = "AVAILABILITY_DOMAIN_${each.value}"
  admin_enabled            = var.activate
  mtu                      = var.mtu
}
