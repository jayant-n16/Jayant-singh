output "vxc_uids" {
  description = "VXC product UIDs by key."
  value       = { for k, v in megaport_vxc.this : k => v.product_uid }
}

output "provisioning_status" {
  value = { for k, v in megaport_vxc.this : k => v.provisioning_status }
}
