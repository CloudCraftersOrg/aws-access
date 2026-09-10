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
# Each set is backed by either managed_policy_arn (an AWS managed policy) or an
# inline document registered under this same key in local.inline_policies, at
# the top of locals.tf. Nothing here names the document: the set's own name is
# the link, so adding a set with a custom policy is one entry here plus one line
# there. A set with neither fails a precondition in permission_sets.tf rather
# than silently provisioning with only the region lockdown.
variable "permission_sets" {
  type = map(object({
    description        = string
    session_duration   = optional(string, "PT8H")
    managed_policy_arn = optional(string)
    allowed_regions    = optional(list(string))
  }))
  description = "Permission sets to create, keyed by name."

  default = {
    # allowed_regions is set even though this set carries AdministratorAccess:
    # region_restriction is merged into every set, so leaving it null pinned the
    # org's admins to us-west-2 alone and any us-east-1 call came back as an
    # explicit deny. us-east-1 is where the partner services (AWS Transform,
    # MGN) live, and admins have to be able to reach them to validate the
    # cohort's access.
    #
    # us-east-2 carries no workload and is here only for Bedrock cross-region
    # inference profiles. A `us.*` model ID fans a single request out across
    # us-east-1, us-east-2 and us-west-2, and each leg authorizes against the
    # region it lands in, not the region the call was made from. With us-east-2
    # missing, invoking `us.amazon.nova-2-lite-v1:0` from us-east-1 failed with
    # an explicit deny naming an us-east-2 ARN, which reads like a us-east-1
    # problem and is not one. Admins have to be able to reach the profile IDs to
    # reproduce what the cohort's Lambda roles do at runtime — those roles carry
    # no region cap, since require_boundary is false everywhere and no SCP
    # restricts regions.
    AdministratorAccess = {
      description        = "Full administrative access to all AWS services"
      managed_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
      allowed_regions    = ["us-east-1", "us-east-2", "us-west-2"]
    }
    # The general-purpose read set, and the baseline every other set builds on.
    ReadOnlyAccess = {
      description        = "Read-only access to all resources across the organization"
      managed_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    }
    DevOpsAgentAccess = {
      description     = "Diagnose common AWS infrastructure and deploy the helper resources used by AWS DevOps Agent demos"
      allowed_regions = ["us-east-1", "us-west-2"]
    }
    AWSTransformAccess = {
      description     = "AWS Transform demo cohort: web app sign-in plus deploying the fbctf demo app"
      allowed_regions = ["us-west-2", "us-east-1"]
    }

    # Every AWS region in the Americas. Write still stays confined to the
    # controls and to AIGovernance-* resources by the ai_governance_access document.
    AIGovernanceAccess = {
      description = "Inventory, govern and audit AI service usage across the Americas"
      allowed_regions = [
        "ca-central-1", "ca-west-1", "mx-central-1", "sa-east-1",
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
      ]
    }
    # The admin-grade counterpart of AIGovernanceAccess, for the agent governance
    # offering: enforcing controls org-wide means creating and attaching SCPs,
    # registering delegated administrators and enabling service access, none of
    # which is possible from a member account or from a least-privilege set.
    #
    # Near-admin rather than AdministratorAccess. The ai_governance_admin_access
    # document allows everything, then denies the surfaces that would let a
    # holder dismantle the governance system they operate inside: irreversible
    # organization changes, Identity Center writes (which is how you would grant
    # yourself more), the audit trail, the Terraform state, and the CI roles.
    #
    # Deliberately a shorter session than the rest. This is the widest set in the
    # repo and the only one granted on the management account, where SCPs do not
    # apply.
    AIGovernanceAdminAccess = {
      description      = "Agent governance operator: near-admin on the management account for org-wide AI controls"
      session_duration = "PT4H"
      allowed_regions = [
        "ca-central-1", "ca-west-1", "mx-central-1", "sa-east-1",
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
      ]
    }
    # Edge AI Landing Zone pilot. No allowed_regions override, so it's capped to var.region.
    EdgeAIAccess = {
      description = "Edge AI Landing Zone pilot: govern model delivery, fleet control and inference observability for edge/IoT devices"
    }
  }

  # Requires at least one component, so the degenerate "PT" fails here rather than
  # being rejected by AWS at apply.
  validation {
    condition = alltrue([
      for k, v in var.permission_sets :
      can(regex("^PT(([0-9]+H)([0-9]+M)?|([0-9]+M))$", v.session_duration))
    ])
    error_message = "session_duration must be an ISO-8601 duration with at least one component, such as PT8H, PT90M or PT1H30M."
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
      Administrators = ["AdministratorAccess", "ReadOnlyAccess"]

      # The only non-Administrators grant on the management account, and the
      # only place AIGovernanceAdminAccess is granted. Organizations write, delegated
      # administrator registration and SCP management only work from here, and
      # the agent governance offering needs all three.
      #
      # The AIGovernance group already exists in the base repo, so this line is
      # the entire change: nothing has to be added there first.
      AIGovernance = ["AIGovernanceAdminAccess"]
    }

    # ReadOnly is the baseline group: every user in the base repo belongs to it. So
    # a ReadOnly grant on an account means "everyone can look at this account",
    # which is why it is here and on Sandbox but deliberately NOT on Production
    # below.
    Development = {
      Administrators = ["AdministratorAccess", "ReadOnlyAccess"]
      ReadOnly       = ["ReadOnlyAccess"]
    }

    # Administrators only. Now that ReadOnly means everyone, granting it here
    # would hand the whole organization read access to production, which is the
    # opposite of the intent: production visibility should be deliberate.
    #
    # This does mean nobody outside Administrators can see production. A narrower
    # audience for it needs its own group in the base repo: ReadOnly cannot serve
    # as the gate, because everyone is in it.
    Production = {
      Administrators = ["AdministratorAccess", "ReadOnlyAccess"]
    }

    # The admin bundle stays at the two general sets, so a cohort set only ever
    # reaches its cohort. Exercising AWSTransformAccess means joining AWSTransform
    # in the base repo, the same as every other specialised set.
    Sandbox = {
      Administrators = ["AdministratorAccess", "ReadOnlyAccess"]
      ReadOnly       = ["ReadOnlyAccess"]
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

  # Retiring a permission set means deleting it from every list here, and a list
  # that empties out produces no assignments while still passing every other
  # check. The group would silently lose all access on that account, and the plan
  # would show only destroys, which is what an intended revocation looks like too.
  #
  # So an empty list is rejected: to actually revoke, delete the group key.
  validation {
    condition = alltrue(flatten([
      for account, groups in var.grants : [
        for group, permsets in groups : length(permsets) > 0
      ]
    ]))
    error_message = "A group listed under an account must be granted at least one permission set. Remove the group key entirely to revoke its access on that account."
  }
}

###########################################################
# Resource names the policies scope to
###########################################################
#
# Alphabetical within this section. The two sections above are not folded into
# it, and the file is not alphabetical end to end, which is a deliberate
# departure from the Terraform style guide: permission_sets and grants are what
# a reviewer reads to approve an access change, and sorting the whole file would
# bury them under prefixes like demo_app_prefix. Grouped by purpose, then sorted
# inside each group.

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

# The permissions boundary that roles created through a permission set must
# carry. Created by the base repo's bootstrap stack in every account, because
# this stack has no iam:CreatePolicy and runs against the management account
# only, so it can neither create it nor reach the member accounts to do so.
#
# This is a third entry in the name contract between the two repos, alongside
# account names and group display names: it is matched as
# arn:aws:iam::*:policy/<this name>, which is also why no account ID is needed.
# Renaming it in the base repo breaks iam:CreateRole for every permission set
# that requires it, so coordinate the rename in the same window.
#
# Why a boundary at all: several of the policies_*.tf documents grant
# iam:CreateRole together with iam:AttachRolePolicy on a role name prefix.
# AttachRolePolicy's resource is the role, not the policy being attached, so
# without a boundary a holder could create a role inside their prefix, attach
# AdministratorAccess to it, point its trust policy at themselves and assume it.
# iam:* and sts:* are exempt from the region lockdown and no SCP covers it, so
# the boundary is the containment.
variable "role_boundary_policy_name" {
  type        = string
  description = "Name of the permissions boundary, created by the base repo, required on roles created through a permission set."
  default     = "DelegatedRoleBoundary"
}

# Prefix the transform-agents PoC stack's DynamoDB, Lambda, ECR, Scheduler, S3,
# Budgets and IAM access is scoped to, in the aws_transform_access document.
variable "transform_agents_prefix" {
  type        = string
  description = "Resource name prefix for the transform-agents PoC stack."
  default     = "transform-agents"
}

# Prefix the transform-containers PoC stack's Secrets Manager and IAM role access
# is scoped to, in the aws_transform_access document. Security groups are not
# scoped by this prefix despite an earlier comment here saying so: EC2 networking
# comes from the account-wide ec2:* in FbctfInfraDeploy.
variable "transform_container_prefix" {
  type        = string
  description = "Resource name prefix for the ECS containers PoC stack."
  default     = "transform-containers"
}


# Resource name prefix for the Edge AI Landing Zone pilot's resources.
variable "edge_ai_prefix" {
  type        = string
  description = "Resource name prefix for the Edge AI Landing Zone pilot."
  default     = "edge-ai"
}
