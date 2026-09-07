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
