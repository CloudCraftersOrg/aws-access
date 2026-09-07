# A module needs its own provider requirements. No provider block: it inherits
# the root's configuration, which is what a module without an explicit
# `providers` argument does.
#
# This module creates no resources. Every block in it is a data source that the
# AWS provider renders locally, so nothing here reaches AWS and nothing here has
# a presence in state that would need moving.

terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
