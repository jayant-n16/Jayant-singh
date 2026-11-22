output "bucket" {
  description = "State bucket name (OPLIA_TF_STATE_BUCKET)."
  value       = aws_s3_bucket.state.id
}

output "lock_table" {
  description = "DynamoDB lock table name (OPLIA_TF_LOCK_TABLE)."
  value       = aws_dynamodb_table.lock.name
}

output "kms_key_arn" {
  description = "KMS key encrypting state and the lock table."
  value       = local.kms_key_arn
}

output "backend_config" {
  description = "Values for `terraform init -backend-config=...` with an empty `backend \"s3\" {}` block."
  value = {
    bucket         = aws_s3_bucket.state.id
    dynamodb_table = aws_dynamodb_table.lock.name
    encrypt        = true
    kms_key_id     = local.kms_key_arn
  }
}
