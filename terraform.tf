# Version constraints only. The backend is in backend.tf and the provider
# configuration in providers.tf, which the Terraform style guide recommends
# keeping apart; a configuration may hold more than one terraform block.

terraform {
  # 1.10 is the floor for use_lockfile in backend.tf.
  required_version = ">= 1.10.0"

  # Pinned to the 6.x line rather than left open at >= 5.0. .terraform.lock.hcl
  # is what fixes the exact version, but a major-version ceiling stops a future
  # `init -upgrade` from silently crossing a breaking change in a stack whose
  # only job is granting access.
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
