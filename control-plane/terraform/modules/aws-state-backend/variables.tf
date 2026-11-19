variable "bucket_name" {
  description = "Globally unique S3 bucket name for Terraform state."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.bucket_name)) && !can(regex("\\.\\.", var.bucket_name))
    error_message = "bucket_name must be 3-63 chars of lowercase letters, digits, dots and hyphens."
  }
}

variable "lock_table_name" {
  description = "DynamoDB table used for state locking."
  type        = string
  default     = "terraform-state-lock"
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]{3,255}$", var.lock_table_name))
    error_message = "lock_table_name must be 3-255 chars of letters, digits, '_', '-' or '.'."
  }
}

variable "kms_key_arn" {
  description = "Existing KMS key ARN for state encryption. When null, a dedicated key with rotation is created."
  type        = string
  default     = null
}

variable "noncurrent_version_retention_days" {
  description = "Days to keep previous state versions (for recovery from a bad apply)."
  type        = number
  default     = 90
  validation {
    condition     = var.noncurrent_version_retention_days >= 7 && var.noncurrent_version_retention_days <= 3650
    error_message = "noncurrent_version_retention_days must be between 7 and 3650."
  }
}

variable "access_log_bucket" {
  description = "Optional existing bucket that receives S3 server access logs for the state bucket."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
