output "connection_ids" {
  description = "Fabric connection UUIDs by key and leg."
  value = merge(
    { for k, c in equinix_fabric_connection.primary : k => c.id },
    { for k, c in equinix_fabric_connection.secondary : k => c.id },
  )
}
