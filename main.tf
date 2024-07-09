// This module creates a single EC2 instance for running a Minecraft server

##################################################
# Networking
##################################################
data "aws_vpc" "default" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.default.id
}

data "aws_subnet" "selected" {
  id = local.subnet_id
}

resource "aws_subnet" "minecaft_subnet" {
  vpc_id                  = aws_vpc.default.id
  cidr_block              = "10.0.0.0/24"
  map_public_ip_on_launch = true

  depends_on = [aws_internet_gateway.gw]
}

resource "aws_network_interface" "ec2_minecraft" {
  subnet_id   = aws_subnet.private_subnet.id
  private_ips = ["10.0.0.100"]

  tags = {
    Name = "primary_network_interface"
  }
}

resource "aws_eip" "minecraft_ip" {
  domain = "vpc"

  instance                  = aws_instance.ec2_minecraft.id
  associate_with_private_ip = "10.0.0.10"
  depends_on                = [aws_internet_gateway.gw]
}

##################################################
# Network Security
##################################################
resource "aws_security_group" "ec2_security_group" {
  name        = "${var.name}-ec2"
  description = "Allow SSH and TCP ${var.mc_port}"
  vpc_id      = aws_vpc.default.id
}

resource "aws_vpc_security_group_ingress_rule" "allow_ssh_ipv4"{
  for_each = toset(var.allowed_cidrs)
  security_group_id = aws_security_group.ec2_security_group.id
  cidr_ipv4         = each.value
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "allow_https_ipv4"{
  for_each = toset(var.allowed_cidrs)
  security_group_id = aws_security_group.ec2_security_group.id
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "allow_outbound_java_tcp_ipv4"{
  for_each = toset(var.allowed_cidrs)
  security_group_id = aws_security_group.ec2_security_group.id
  cidr_ipv4         = each.value
  from_port         = 25565 
  to_port           = 25565 
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "allow_outbound_java_udp_ipv4"{
  for_each = toset(var.allowed_cidrs)
  security_group_id = aws_security_group.ec2_security_group.id
  cidr_ipv4         = each.value
  from_port         = 25565 
  to_port           = 25565 
  ip_protocol       = "udp"
}

resource "aws_vpc_security_group_egress_rule" "allow_outbound_bedrock_tcp_ipv4"{
  for_each = toset(var.allowed_cidrs)
  security_group_id = aws_security_group.ec2_security_group.id
  cidr_ipv4         = each.value
  from_port         = 19132 
  to_port           = 19133
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "allow_outbound_bedrock_udp_ipv4"{
  for_each = toset(var.allowed_cidrs)
  security_group_id = aws_security_group.ec2_security_group.id
  cidr_ipv4         = each.value
  from_port         = 19132 
  to_port           = 19133 
  ip_protocol       = "udp"
}


data "aws_caller_identity" "aws" {}

locals {
  subnet_id = length(var.subnet_id) > 0 ? var.subnet_id : sort(data.aws_subnet_ids.default.ids)[0]
  tf_tags = {
    Terraform = true,
    By        = data.aws_caller_identity.aws.arn
  }
}

# // Keep labels, tags consistent
# module "label" {
#   source     = "git::ssh://github.com/cloudposse/terraform-null-label.git?ref=master"

#   namespace   = var.namespace
#   stage       = var.environment
#   name        = var.name
#   delimiter   = "-"
#   label_order = ["environment", "stage", "name", "attributes"]
#   tags        = merge(var.tags, local.tf_tags)
# }


##################################################
# EC2
##################################################

#  Amazon Linux2 AMI - can switch this to default by editing the EC2 resource below
data "aws_ami" "amazon-linux-2" {
  most_recent = true

  owners = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm*"]
  }
}

# Find latest Ubuntu AMI, use as default if no AMI specified
data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

resource "aws_instance" "ec2_minecraft" {
  ami                  = var.ami != "" ? var.ami : data.aws_ami.ubuntu.id
  instance_type        = var.instance_type
  
  network_interface {
    network_interface_id = aws_network_interface.ec2_minecraft.id
    device_index         = 0
  }

  # Key name of the Key Pair to use for the instance; which can be managed using the aws_key_pair resource.
  key_name             = local._ssh_key_name

  # IAM Instance Profile to launch the instance with. Specified as the name of the Instance Profile. Ensure your credentials have the correct permission to assign the instance profile according to the EC2 documentation, notably iam:PassRole.
  iam_instance_profile = aws_iam_instance_profile.mc.id

  user_data            = data.template_file.user_data.rendered

  tags = module.label.tags
}


##################################################
# S3 Bucket Storage
##################################################

#  S3 bucket for persisting minecraft
resource "random_string" "s3" {
  length  = 12
  special = false
  upper   = false
}

locals {
  using_existing_bucket = signum(length(var.bucket_name)) == 1
  bucket = length(var.bucket_name) > 0 ? var.bucket_name : "${module.label.id}-${random_string.s3.result}"
}

resource "aws_s3_bucket" "s3_bucket" {
  bucket = local.bucket
  force_destroy = var.bucket_force_destroy
  
}

resource "aws_s3_bucket_ownership_controls" "s3_bucket_ownership_controls" {
  count = local.using_existing_bucket ? 1 : 0

  bucket = aws_s3_bucket.s3_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "s3_bucket_acl" {
  count = local.using_existing_bucket ? 1 : 0

  depends_on = [aws_s3_bucket_ownership_controls.s3_bucket_ownership_controls]

  bucket = aws_s3_bucket.s3_bucket.id
  acl    = "private"
}

resource "aws_s3_bucket_versioning" "s3_bucket_versioning" {
  count = local.using_existing_bucket ? 1 : 0

  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = var.bucket_object_versioning
  }
}

resource "aws_s3_bucket_public_access_block" "s3_bucket_public_access_block" {
  count = local.using_existing_bucket ? 1 : 0
  
  bucket = aws_s3_bucket.s3_bucket.id

  # S3 bucket-level Public Access Block configuration
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#  IAM role for S3 access
resource "aws_iam_role" "allow_s3" {
  name   = "${module.label.id}-allow-ec2-to-s3"
  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
  })
}

resource "aws_iam_instance_profile" "mc" {
  name = "${module.label.id}-instance-profile"
  role = aws_iam_role.allow_s3.name
}

resource "aws_iam_role_policy" "mc_allow_ec2_to_s3" {
  name   = "${module.label.id}-allow-ec2-to-s3"
  role   = aws_iam_role.allow_s3.id
  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": ["s3:ListBucket"],
        "Resource": ["arn:aws:s3:::${local.bucket}"]
      },
      {
        "Effect": "Allow",
        "Action": [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject"
        ],
        "Resource": ["arn:aws:s3:::${local.bucket}/*"]
      }
    ]
  })
}

# Script to configure the server - this is where most of the magic occurs!
data "template_file" "user_data" {
  template = file("${path.module}/user_data.sh")

  vars = {
    mc_root        = var.mc_root
    mc_bucket      = local.bucket
    mc_backup_freq = var.mc_backup_freq
    mc_version     = var.mc_version
    mc_type        = var.mc_type   
    java_mx_mem    = var.java_mx_mem
    java_ms_mem    = var.java_ms_mem
  }
}


# Create EC2 ssh key pair
resource "tls_private_key" "ec2_ssh" {
  count = length(var.key_name) > 0 ? 0 : 1

  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "ec2_ssh" {
  count = length(var.key_name) > 0 ? 0 : 1

  key_name   = "${var.name}-ec2-ssh-key"
  public_key = tls_private_key.ec2_ssh[0].public_key_openssh
}

locals {
  _ssh_key_name = length(var.key_name) > 0 ? var.key_name : aws_key_pair.ec2_ssh[0].key_name
}


