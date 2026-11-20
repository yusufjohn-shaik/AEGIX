resource "aws_security_group" "internal_ssh_bastion" {
  name        = "internal_ssh_bastion"
  description = "Restricted SSH from internal VPN"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_s3_bucket" "secure_vault" {
  bucket = "company-hardened-vault"

  logging {
    target_bucket = "company-access-logs"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault_encryption" {
  bucket = aws_s3_bucket.secure_vault.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

variable "db_instance_type" {
  type        = string
  description = "EC2 instance type"
  default     = "db.t4g.micro"
}
