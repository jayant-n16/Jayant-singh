variable "name" {
  type = string
}

variable "project" {
  type = string
}

variable "region" {
  type = string
}

variable "network" {
  description = "VPC network self link or name."
  type        = string
}

variable "availability_domains" {
  description = "\"1\" and \"2\" for the 99.99 % topology."
  type        = list(string)
  default     = ["1", "2"]
  validation {
    condition     = length(var.availability_domains) > 0 && alltrue([for d in var.availability_domains : contains(["1", "2"], d)])
    error_message = "availability_domains may contain only \"1\" and \"2\"."
  }
}

variable "activate" {
  description = "Set true after the partner has provisioned the attachments."
  type        = bool
  default     = false
}

variable "mtu" {
  type    = string
  default = "1440"
}
