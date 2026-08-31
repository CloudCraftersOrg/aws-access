# Nothing here is secret. Every variable runs on its committed default; the
# workflow sets no TF_VAR_* and passes no -var-file.
#
# The resource names at the bottom are the exception to "no names in a public
# repo": they are targets the policies grant on, not credentials.

variable "region" {
  type        = string
  description = "Region for Identity Center and the default region lockdown."
  default     = "us-west-2"
}

###########################################################
# Permission sets
###########################################################

# `name` is immutable in AWS: renaming a key destroys and recreates the
# permission set and drops every assignment pointing at it.
#
# Each set is backed by either managed_policy_arn (an AWS managed policy) or
# inline_policy_key (a document in policies.tf). The key is not the set's name;
# policies.tf opens with the full mapping.
variable "permission_sets" {
  type = map(object({
    description        = string
    session_duration   = optional(string, "PT8H")
    managed_policy_arn = optional(string)
    inline_policy_key  = optional(string)
    allowed_regions    = optional(list(string))
  }))
  description = "Permission sets to create, keyed by name."

  default = {
    AdministratorAccess = {
      description        = "Full administrative access to all AWS services"
      managed_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    }
    # Not the AWS managed PowerUserAccess policy. See policies.tf.
    PowerUserAccess = {
      description       = "Read-only view of the CloudWatch Agent's resources, plus invoking its AgentCore runtime for demos"
      inline_policy_key = "power_user_access"
    }
    ReadOnlyAccess = {
      description        = "Read-only access to all resources across the organization"
      managed_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    }
    WorkshopOnlyAccess = {
      description       = "Modify existing workshop infra (no create/destroy) plus invoke AgentCore runtime"
      inline_policy_key = "infra_modify_only"
    }
    DevOpsAgentAccess = {
      description       = "Diagnose common AWS infrastructure and deploy the helper resources used by AWS DevOps Agent demos"
      inline_policy_key = "devops_agent_access"
      allowed_regions   = ["us-east-1", "us-west-2"]
    }
    AWSTransformAccess = {
      description       = "AWS Transform demo cohort: web app sign-in plus deploying the fbctf demo app"
      inline_policy_key = "partner_demo_access"
      allowed_regions   = ["us-west-2", "us-east-1"]
    }
    # us-east-1 as well, or an auditor cannot see the Bedrock and AWS Transform
    # activity that already happens there.
    AIGovernance = {
      description       = "Audit AI service usage and manage the Bedrock guardrails constraining it"
      inline_policy_key = "ai_governance"
      allowed_regions   = ["us-west-2", "us-east-1"]
    }
  }

  validation {
    condition = alltrue([
      for k, v in var.permission_sets :
      contains(["power_user_access", "infra_modify_only", "devops_agent_access", "partner_demo_access", "ai_governance"], v.inline_policy_key)
      if v.inline_policy_key != null
    ])
    error_message = "inline_policy_key must be one of: power_user_access, infra_modify_only, devops_agent_access, partner_demo_access, ai_governance."
  }

  validation {
    condition = alltrue([
      for k, v in var.permission_sets :
      can(regex("^PT([0-9]+H)?([0-9]+M)?$", v.session_duration))
    ])
    error_message = "session_duration must be an ISO-8601 duration such as PT8H or PT1H30M."
  }
}

###########################################################
# Grants
###########################################################

# Account name -> group display name -> permission sets.
#
# Account keys are literal AWS account names, except `management`, which is a
# reserved alias for the organization's management account. Group keys are
# Identity Center display names. Both must match what the base repo created, or
# the run fails during lookup; see the check blocks in lookups.tf.
variable "grants" {
  type        = map(map(list(string)))
  description = "AWS account name -> Identity Center group display name -> permission set names."

  default = {
    # `management` is a reserved alias resolved to the organization's management
    # account, whatever it happens to be named. Every other key is a literal
    # account name.
    management = {
      Administrators = ["AdministratorAccess", "PowerUserAccess", "ReadOnlyAccess"]
    }

    Development = {
      Administrators = ["AdministratorAccess", "PowerUserAccess", "ReadOnlyAccess"]
      Developers     = ["PowerUserAccess"]
      InfraModifiers = ["WorkshopOnlyAccess"]
    }

    Production = {
      Administrators = ["AdministratorAccess", "PowerUserAccess", "ReadOnlyAccess"]
      Developers     = ["PowerUserAccess"]
      InfraModifiers = ["WorkshopOnlyAccess"]
      ReadOnly       = ["ReadOnlyAccess"]
    }

    # Workshops gets PowerUserAccess, which here is read-only. Administrators
    # also carry AWSTransformAccess so that set can be validated without
    # joining the cohort group.
    Sandbox = {
      Administrators = ["AdministratorAccess", "PowerUserAccess", "ReadOnlyAccess", "AWSTransformAccess"]
      Workshops      = ["PowerUserAccess"]
      DevOpsAgent    = ["DevOpsAgentAccess"]
      AWSTransform   = ["AWSTransformAccess"]
      AIGovernance   = ["AIGovernance"]
    }
  }

  validation {
    condition = alltrue(flatten([
      for account, groups in var.grants : [
        for group, permsets in groups : [
          for permset in permsets : contains(keys(var.permission_sets), permset)
        ]
      ]
    ]))
    error_message = "Every permission set in grants must be declared in permission_sets."
  }

  validation {
    condition = alltrue(flatten([
      for account, groups in var.grants : [
        for group, permsets in groups : length(permsets) == length(distinct(permsets))
      ]
    ]))
    error_message = "A group cannot be granted the same permission set twice on one account."
  }
}

###########################################################
# Resource names the policies scope to
###########################################################

# Buckets the modify-only permission set may read and write, so holders can run
# `terraform apply` against existing workshop infrastructure.
variable "state_bucket_names" {
  type        = list(string)
  description = "S3 buckets the modify-only permission set may read/write for Terraform state."
  default     = ["cloudcrafters-workshop-2026-tfstate"]
}

# Resource prefix scoping the demo stack's IAM, S3 and Secrets Manager access.
# Everything that stack creates must carry this prefix or it hits those denials.
variable "demo_app_prefix" {
  type        = string
  description = "Resource name prefix for the demo application stack."
  default     = "fbctf"
}

# The partner service is not available in var.region.
variable "demo_app_region" {
  type        = string
  description = "Region hosting the partner demo web application."
  default     = "us-east-1"
}
