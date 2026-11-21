# AWS Global Accelerator in front of the per-cloud public entry points (Phase 4 of the rollout).
#
# Global Accelerator endpoints are AWS resources (ALB, NLB, EC2 instance or Elastic IP). Azure,
# GCP and IBM entry points are reached through an NLB or EIP in the nearest AWS region that
# forwards to them over the private interconnect (Equinix Fabric or Megaport), so each cloud is one
# endpoint group whose share of traffic is controlled with the traffic dial.
#
# Traffic dial ownership: Terraform sets the initial dial only. Every later change is made by
# OPLIA as a gated, audited `network.traffic_dial` proposal (UpdateEndpointGroup), so the
# attribute is in ignore_changes - otherwise the next plan would silently undo an approved step.

resource "aws_globalaccelerator_accelerator" "this" {
  name            = var.name
  ip_address_type = var.ip_address_type
  enabled         = var.enabled

  attributes {
    flow_logs_enabled   = true
    flow_logs_s3_bucket = var.flow_logs_s3_bucket
    flow_logs_s3_prefix = var.flow_logs_s3_prefix
  }

  tags = var.tags
}

resource "aws_globalaccelerator_listener" "this" {
  for_each = var.listeners

  accelerator_arn = aws_globalaccelerator_accelerator.this.arn
  protocol        = each.value.protocol
  client_affinity = each.value.client_affinity

  dynamic "port_range" {
    for_each = each.value.port_ranges
    content {
      from_port = port_range.value.from_port
      to_port   = port_range.value.to_port
    }
  }
}

resource "aws_globalaccelerator_endpoint_group" "this" {
  for_each = var.endpoint_groups

  listener_arn                  = aws_globalaccelerator_listener.this[each.value.listener].arn
  endpoint_group_region         = each.value.region
  health_check_protocol         = each.value.health_check_protocol
  health_check_port             = each.value.health_check_port
  health_check_path             = each.value.health_check_protocol == "TCP" ? null : each.value.health_check_path
  health_check_interval_seconds = each.value.health_check_interval_seconds
  threshold_count               = each.value.threshold_count
  traffic_dial_percentage       = each.value.initial_traffic_dial

  dynamic "endpoint_configuration" {
    for_each = each.value.endpoints
    content {
      endpoint_id                    = endpoint_configuration.value.endpoint_id
      weight                         = endpoint_configuration.value.weight
      client_ip_preservation_enabled = endpoint_configuration.value.client_ip_preservation_enabled
    }
  }

  lifecycle {
    ignore_changes = [traffic_dial_percentage]
  }
}
