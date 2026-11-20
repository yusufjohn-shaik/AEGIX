resource "aws_security_group" "allow_ssh_world" {
  name        = "allow_ssh_world"
  description = "Insecure open SSH to world"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "company-public-data-vault"
}

variable "database_password" {
  type        = string
  description = "Database administrator password"
  default     = "SuperSecretAdmin123!"
}

locals {
  api_secret_key = "sk_live_99887766554433221100"
}
