output "pairing_keys" {
  description = "Pairing key by availability domain - give these to the partner."
  value       = { for d, a in google_compute_interconnect_attachment.this : d => a.pairing_key }
  sensitive   = true
}

output "attachment_states" {
  value = { for d, a in google_compute_interconnect_attachment.this : d => a.state }
}
