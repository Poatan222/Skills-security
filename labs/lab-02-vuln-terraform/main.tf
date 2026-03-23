# LAB-02: Deliberately Vulnerable Terraform
# Tests: Wildcard IAM, open SGs, public S3, IMDSv1, hardcoded secrets
# DO NOT APPLY — for skill testing only

provider "aws" {
  region = "us-east-1"
}

# VULN: Wildcard IAM policy — Critical
resource "aws_iam_policy" "wildcard_policy" {
  name = "vuln-wildcard-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# VULN: S3 bucket publicly accessible — Critical
resource "aws_s3_bucket" "public_bucket" {
  bucket = "company-prod-data-public"
  acl    = "public-read-write"
}

resource "aws_s3_bucket_public_access_block" "bad" {
  bucket                  = aws_s3_bucket.public_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# VULN: Security group open SSH to world — Critical
resource "aws_security_group" "open_sg" {
  name = "vuln-open-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# VULN: EC2 with IMDSv1 + hardcoded secret in user_data — High
resource "aws_instance" "vuln_ec2" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  security_groups = [aws_security_group.open_sg.name]

  metadata_options {
    http_tokens = "optional"  # IMDSv1 enabled
  }

  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="super_secret_prod_password_123"
    export API_KEY="sk-prod-abcdef1234567890"
    echo $DB_PASSWORD > /etc/app/config
  EOF
}

# VULN: RDS publicly accessible + no encryption — High
resource "aws_db_instance" "vuln_rds" {
  identifier        = "vuln-prod-db"
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  username          = "admin"
  password          = "Password123!"
  publicly_accessible = true
  storage_encrypted   = false
  deletion_protection = false
}
