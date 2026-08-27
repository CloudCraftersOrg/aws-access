# Standalone stack with its own state. It does not read the base stack's state:
# accounts, groups and the Identity Center instance are discovered from AWS in
# lookups.tf, which is what keeps account IDs out of this repository.

terraform {
  # 1.10 is the floor for use_lockfile below.
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }

  # Partial configuration: `bucket` and `key` are passed at init time, because
  # the bucket name is the one part of this that should not be committed.
  #
  # The region is repeated rather than taken from var.region: backend blocks
  # cannot reference variables.
  #
  # use_lockfile turns on S3-native state locking. Without it the -lock-timeout
  # flags in the workflow do nothing and two concurrent applies could both write
  # state. It writes a .tflock object next to the state key, which the role's S3
  # policy already covers because that policy is scoped to the whole prefix.
  backend "s3" {
    region       = "us-west-2"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region

  # Matches the base stack exactly. Adding a tag here would rewrite every
  # permission set on the next apply.
  default_tags {
    tags = {
      Created_by = "Terraform"
    }
  }
}
