# Remote Terraform state on AWS: S3 bucket (versioned, KMS-encrypted, private, TLS-only)
# plus a DynamoDB table for state locking. Locking is what prevents two concurrent runs
# (for example a drift remediation and a TTL teardown) from corrupting the same state.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40, < 7.0"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  create_kms_key = var.kms_key_arn == null
  kms_key_arn    = local.create_kms_key ? aws_kms_key.state[0].arn : var.kms_key_arn
}

# --------------------------------------------------------------------------- KMS
data "aws_iam_policy_document" "kms" {
  count = local.create_kms_key ? 1 : 0

  # The account root principal administers the key; IAM policies in the account then
  # grant pipeline roles kms:Encrypt/Decrypt/GenerateDataKey. In a key policy the
  # resource "*" refers to this key only.
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "state" {
  count                   = local.create_kms_key ? 1 : 0
  description             = "OPLIA Terraform state encryption (${var.bucket_name})"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms[0].json
  tags                    = var.tags
}

resource "aws_kms_alias" "state" {
  count         = local.create_kms_key ? 1 : 0
  name          = "alias/${var.bucket_name}"
  target_key_id = aws_kms_key.state[0].key_id
}

# ------------------------------------------------------------------- S3 bucket
resource "aws_s3_bucket" "state" {
  #checkov:skip=CKV_AWS_144:State is versioned and KMS-encrypted; cross-region replication needs a second-region bucket the caller owns.
  #checkov:skip=CKV2_AWS_62:No consumer for object events on a state bucket; access is audited through CloudTrail/access logs.
  bucket        = var.bucket_name
  force_destroy = false
  tags          = var.tags
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    id     = "expire-noncurrent-state-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_retention_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.state]
}

resource "aws_s3_bucket_logging" "state" {
  count         = var.access_log_bucket == null ? 0 : 1
  bucket        = aws_s3_bucket.state.id
  target_bucket = var.access_log_bucket
  target_prefix = "s3-access/${var.bucket_name}/"
}

data "aws_iam_policy_document" "bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.state.arn,
      "${aws_s3_bucket.state.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket     = aws_s3_bucket.state.id
  policy     = data.aws_iam_policy_document.bucket.json
  depends_on = [aws_s3_bucket_public_access_block.state]
}

# --------------------------------------------------------------- DynamoDB lock
resource "aws_dynamodb_table" "lock" {
  name                        = var.lock_table_name
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "LockID"
  deletion_protection_enabled = true

  attribute {
    name = "LockID"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = local.kms_key_arn
  }

  tags = var.tags
}
