# Inputs are the resource names the policies scope to, plus the permission sets
# themselves, which the region lockdown iterates over. The root passes its own
# variables straight through; the descriptions there are the canonical ones.

variable "demo_app_prefix" {
  type        = string
  description = "Resource name prefix for the demo application stack."
}

variable "demo_app_region" {
  type        = string
  description = "Region hosting the partner demo web application."
}

variable "permission_sets" {
  type = map(object({
    description        = string
    session_duration   = optional(string, "PT8H")
    managed_policy_arn = optional(string)
    allowed_regions    = optional(list(string))
  }))
  description = "Permission sets to build policies for, keyed by name. Only allowed_regions is read here."
}

variable "region" {
  type        = string
  description = "Default region for the lockdown, used when a set sets no allowed_regions."
}

variable "role_boundary_policy_name" {
  type        = string
  description = "Name of the permissions boundary required on roles these policies allow creating."
}

variable "transform_agents_prefix" {
  type        = string
  description = "Resource name prefix for the transform-agents PoC stack."
}

variable "transform_container_prefix" {
  type        = string
  description = "Resource name prefix for the ECS containers PoC stack."
}
