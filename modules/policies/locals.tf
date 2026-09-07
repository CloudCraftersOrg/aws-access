# WHICH POLICY BACKS WHICH PERMISSION SET
#
# local.inline_policies below is that mapping, and it is the only copy. It is
# keyed by permission set name, so there is no separate table to keep accurate
# and no indirection key to register in three places. A set absent from the map
# carries an AWS managed policy instead; a set in neither fails the precondition
# in the root's permission_sets.tf.
#
# Document names are snake_case and do not have to match the set that consumes
# them, which is why the map is worth reading rather than guessing.
#
# HOW THE LINK IS MADE
#
#   1. locals.tf   local.inline_policies["DevOpsAgentAccess"]
#                    = data.aws_iam_policy_document.devops_agent_access,
#                      defined in devops_agent.tf
#
#   2. outputs.tf  that document, merged with region_restriction and the
#                  role-creation guardrail from shared.tf, becomes the set's
#                  single inline policy
#
# Every set gets `region_restriction` merged in, including the ones carrying an
# AWS managed policy — so a managed policy is still capped to its set's regions.
#
# To add a document: define it in the file for its audience, then register it
# under the permission set's name below. That is the whole change.

locals {
  # Permission set name => policy JSON. The single source of this mapping.
  # Documents are grouped by audience across devops_agent.tf, aws_transform.tf,
  # ai_governance.tf and edge_ai.tf.
  inline_policies = {
    AIGovernanceAccess      = data.aws_iam_policy_document.ai_governance_access.json
    AIGovernanceAdminAccess = data.aws_iam_policy_document.ai_governance_admin_access.json
    AWSTransformAccess      = data.aws_iam_policy_document.aws_transform_access.json
    DevOpsAgentAccess       = data.aws_iam_policy_document.devops_agent_access.json
    EdgeAIAccess            = data.aws_iam_policy_document.edge_ai_access.json
  }

  # Sets exempt from the role-creation guardrail merged into everything else.
  # Only true admin belongs here: the guardrail would contain nothing it cannot
  # already reach directly, and blocking it from repairing a boundary would make
  # an incident worse.
  #
  # AIGovernanceAdminAccess is deliberately NOT exempt even though it is
  # near-admin. The guardrail does not stop it creating roles, only stripping
  # boundaries off other people's and minting IAM users, neither of which the
  # offering needs.
  guardrail_exempt_sets = [
    "AdministratorAccess",
  ]

  # The boundary that every iam:CreateRole statement in this module requires.
  # Matched with ArnLike so the account ID stays a wildcard and none has to be
  # committed to this public repository.
  role_boundary_arn_pattern = "arn:aws:iam::*:policy/${var.role_boundary_policy_name}"
}

# Where a permission set and its policy actually meet. Exposed by outputs.tf.
data "aws_iam_policy_document" "permission_set_inline" {
  for_each = var.permission_sets

  source_policy_documents = compact([
    data.aws_iam_policy_document.region_restriction[each.key].json,
    contains(local.guardrail_exempt_sets, each.key) ? "" : data.aws_iam_policy_document.role_creation_guardrail.json,
    lookup(local.inline_policies, each.key, ""),
  ])

  # The map itself is the check, so there is no second list to keep in sync. A
  # variable validation could not do this: it cannot read a local.
  #
  # A set with neither backing is always a mistake. It would provision with the
  # region lockdown and nothing else, granting no access while looking healthy in
  # the plan.
  lifecycle {
    precondition {
      condition     = each.value.managed_policy_arn != null || contains(keys(local.inline_policies), each.key)
      error_message = "Permission set '${each.key}' has neither managed_policy_arn nor an entry in local.inline_policies, so it would provision with no permissions. Register a document under exactly that name, or set managed_policy_arn."
    }
  }
}
