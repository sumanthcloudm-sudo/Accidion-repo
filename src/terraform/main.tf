provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "insecure_sg" {
  name        = "insecure-security-group"
  description = "Intentional security vulnerabilities"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "accidion-insecure-test-bucket"
}
