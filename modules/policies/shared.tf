# The two policy documents that belong to no single permission set: both are
# merged into every set's inline policy by permission_sets.tf.
#
# The per-set documents are grouped by who holds them:
#
#   devops_agent.tf     DevOpsAgentAccess
#   aws_transform.tf      AWSTransformAccess
#   ai_governance.tf   AIGovernanceAccess, AIGovernanceAdminAccess
#
# local.inline_policies in locals.tf maps each permission set to its document.


# Used by: EVERY permission set, merged into each one's inline policy.
#
# Denies anything outside the set's approved regions. Global and
# region-agnostic services are exempted via not_actions, otherwise console
# sign-in, IAM and billing break everywhere.
#
# for_each over var.permission_sets, so there is one document per set and
# widening one set's allowed_regions does not open that region for the others.
data "aws_iam_policy_document" "region_restriction" {
  for_each = var.permission_sets

  statement {
    sid       = "DenyActionsOutsideApprovedRegion"
    effect    = "Deny"
    resources = ["*"]

    not_actions = [
      "a4b:*",
      "account:*",
      "aws-marketplace:*",
      "aws-marketplace-management:*",
      "aws-portal:*",
      "billing:*",
      "billingconductor:*",
      "budgets:*",
      "ce:*",
      "chime:*",
      "cloudfront:*",
      "consolidatedbilling:*",
      "cur:*",
      "freetier:*",
      "globalaccelerator:*",
      "health:*",
      "iam:*",
      "importexport:*",
      "invoicing:*",
      "organizations:*",
      "payments:*",
      "purchase-orders:*",
      "route53:*",
      "route53domains:*",
      "shield:*",
      "sts:*",
      "support:*",
      "tax:*",
      "trustedadvisor:*",
      "waf:*",
      "waf-regional:*",
      "wafv2:*",
    ]

    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = coalesce(each.value.allowed_regions, [var.region])
    }
  }
}

# Used by: every permission set except those in local.guardrail_exempt_sets,
# merged into each one's inline policy alongside region_restriction.
#
# This is not the boundary. It is what makes the boundary stick. The per-set
# documents require var.role_boundary_policy_name at iam:CreateRole; without
# these denials a holder could create the role correctly and then simply strip
# the boundary off it, which would reopen the escalation the boundary closes.
#
# Merged into sets that never create a role as well. It denies nothing those sets
# do, and keeping it unconditional means a set added later cannot forget it.
data "aws_iam_policy_document" "role_creation_guardrail" {
  statement {
    sid    = "DenyBoundaryRemoval"
    effect = "Deny"
    actions = [
      "iam:DeleteRolePermissionsBoundary",
      "iam:DeleteUserPermissionsBoundary",
    ]
    resources = ["*"]
  }

  # Swapping one boundary for another is the same escape with an extra step, so
  # the replacement has to be the same policy. Conditioned rather than denied
  # outright because Terraform sets the boundary on every apply of a role it
  # manages, and that call has to keep working.
  statement {
    sid    = "DenyBoundaryReplacement"
    effect = "Deny"
    actions = [
      "iam:PutRolePermissionsBoundary",
      "iam:PutUserPermissionsBoundary",
    ]
    resources = ["*"]

    condition {
      test     = "ArnNotLike"
      variable = "iam:PermissionsBoundary"
      values   = [local.role_boundary_arn_pattern]
    }
  }

  # An IAM user is the way around a boundary that only applies to roles: no set
  # here grants these, so this costs nothing and closes that path for good.
  # Long-lived credentials are also the one thing the whole OIDC setup avoids.
  statement {
    sid    = "DenyLongLivedCredentials"
    effect = "Deny"
    actions = [
      "iam:CreateAccessKey",
      "iam:CreateLoginProfile",
      "iam:CreateUser",
      "iam:UpdateAccessKey",
      "iam:UpdateLoginProfile",
    ]
    resources = ["*"]
  }

  # Blocks the shortest path to escalation while require_boundary is off in
  # role_plumbing.tf: create a role inside your prefix, attach an AWS managed
  # admin policy to it, point its trust policy at yourself, assume it.
  #
  # iam:PolicyARN is the policy being attached, not the role, so this reaches the
  # attachment itself. It is not airtight - iam:PutRolePolicy still allows an
  # equivalent inline policy - but it costs nothing operationally, since no stack
  # here has any reason to attach one of these to a role it creates.
  statement {
    sid    = "DenyAdminPolicyAttachment"
    effect = "Deny"
    actions = [
      "iam:AttachRolePolicy",
      "iam:AttachUserPolicy",
    ]
    resources = ["*"]

    condition {
      test     = "ArnLike"
      variable = "iam:PolicyARN"
      values = [
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/IAMFullAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
      ]
    }
  }
}
