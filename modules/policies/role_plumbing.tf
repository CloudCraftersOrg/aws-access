# The IAM plumbing every stack that creates its own roles needs, generated once
# per scope instead of written out per document.
#
# Three statement shapes kept repeating across devops_agent.tf, aws_transform.tf
# and ai_governance.tf, identical except for the ARNs and service names:
#
#   iam:CreateRole              optionally behind the permissions boundary
#   iam:PassRole                behind iam:PassedToService
#   iam:CreateServiceLinkedRole behind iam:AWSServiceName
#
# They are now one table plus one document per entry, composed into the consuming
# policy with source_policy_documents. Adding a stack that manages its own roles
# is an entry in local.role_scopes and one line in the consumer.
#
# What is deliberately NOT collapsed here:
#
#   The scoped IAM *write* statements (DevOpsAgentIamWriteScoped,
#   FbctfIamWriteScoped, TransformAgentsRoles, GovernanceServiceRoles,
#   TransformContainerRoles, AWSTransformCodeBuildExecutionRole). They look alike
#   but their action lists genuinely differ - some carry instance profile verbs,
#   some carry policy verbs, some neither. Folding them into one shape would mean
#   granting the union to all six, which is a permission change disguised as a
#   refactor.
#
#   The path-scoped CreateServiceLinkedRole statements in aws_transform.tf. They
#   name a specific service role ARN instead of conditioning on the service name,
#   so they are a different shape, not a repetition of this one.

locals {
  # One entry per family of roles a permission set may manage.
  #
  # role_arns scopes both CreateRole and PassRole: a stack that may create a role
  # in its prefix is the same stack that hands it to a service. passed_to_services
  # and service_linked_for are optional - an empty list omits that statement
  # rather than emitting one that allows nothing.
  #
  # The map key becomes the sid prefix, so keys are PascalCase to match.
  role_scopes = {
    DevOpsAgent = {
      require_boundary = false
      role_arns = [
        "arn:aws:iam::*:role/demo-*",
        "arn:aws:iam::*:role/devops-agent-*",
      ]
      passed_to_services = [
        "ec2.amazonaws.com",
        "ecs-tasks.amazonaws.com",
        "eks.amazonaws.com",
        "lambda.amazonaws.com",
        "monitoring.rds.amazonaws.com",
      ]
      service_linked_for = [
        "autoscaling.amazonaws.com",
        "ecs.amazonaws.com",
        "eks.amazonaws.com",
        "elasticloadbalancing.amazonaws.com",
        "rds.amazonaws.com",
      ]
    }

    Governance = {
      require_boundary = false
      role_arns        = ["arn:aws:iam::*:role/AIGovernance-*"]
      passed_to_services = [
        "bedrock.amazonaws.com",
        "config.amazonaws.com",
        "ssm.amazonaws.com",
      ]
      service_linked_for = [
        "auditmanager.amazonaws.com",
        "config.amazonaws.com",
      ]
    }

    # Both AWSTransform scopes take CreateRole only. Their PassRole is bundled
    # into the wider write statements in aws_transform.tf, unconditioned, because
    # the service picks the target itself.
    AWSTransformConnector = {
      require_boundary   = false
      role_arns          = ["arn:aws:iam::*:role/service-role/AWSTransform-*"]
      passed_to_services = []
      service_linked_for = []
    }

    AWSTransformCodeBuild = {
      require_boundary = false
      role_arns = [
        "arn:aws:iam::*:role/AWSTransform*",
        "arn:aws:iam::*:role/service-role/AWSTransform*",
      ]
      passed_to_services = []
      service_linked_for = []
    }

    Fbctf = {
      require_boundary   = false
      role_arns          = ["arn:aws:iam::*:role/${var.demo_app_prefix}-*"]
      passed_to_services = ["ec2.amazonaws.com"]
      # Empty on purpose: the ServiceLinkedRoles statement in aws_transform.tf
      # covers this scope's service-linked roles with one path-scoped grant.
      service_linked_for = []
    }

    TransformContainer = {
      require_boundary = false
      role_arns        = ["arn:aws:iam::*:role/${var.transform_container_prefix}-*"]
      passed_to_services = [
        "ecs-tasks.amazonaws.com",
        "ecs.amazonaws.com",
      ]
      service_linked_for = []
    }

    TransformAgents = {
      require_boundary = false
      role_arns        = ["arn:aws:iam::*:role/${var.transform_agents_prefix}-*"]
      passed_to_services = [
        "bedrock-agentcore.amazonaws.com",
        "bedrock.amazonaws.com",
        "lambda.amazonaws.com",
        "scheduler.amazonaws.com",
      ]
      service_linked_for = []
    }
  }
}

data "aws_iam_policy_document" "role_plumbing" {
  for_each = local.role_scopes

  # CreateRole is always its own statement, never folded in with the other role
  # writes, because iam:PermissionsBoundary only exists as a condition key on the
  # CreateRole call. On a statement that also carried AttachRolePolicy the key
  # would be absent, the condition could never match, and the effect would be to
  # deny that action instead of constraining this one.
  #
  # WHY require_boundary IS false EVERYWHERE TODAY
  #
  # Requiring the boundary only works if whatever creates the role sets it, and
  # none of these stacks does:
  #
  #   AWSTransformConnector    The AWS Transform service creates the role when a
  #   AWSTransformCodeBuild    connector request is accepted, and the CodeBuild
  #                            execution role comes from a CloudFormation template
  #                            the service generates. That template has no
  #                            PermissionsBoundary property and is not ours to
  #                            edit, so requiring one denies CreateRole outright
  #                            and the demo cannot run.
  #
  #   Fbctf, TransformAgents,  The cohort's own Terraform. It could set a
  #   TransformContainer,      boundary, but does not today, so turning this on
  #   DevOpsAgent, Governance  breaks their applies until it does.
  #
  # To turn it on for a scope, add
  #
  #   permissions_boundary = "arn:aws:iam::<account>:policy/DelegatedRoleBoundary"
  #
  # to every aws_iam_role in that stack, then flip require_boundary here. The
  # boundary policy already exists in every account, created by the base repo.
  #
  # What contains these scopes with it off: the region lockdown,
  # DenyAdminPolicyAttachment in shared.tf, and role_creation_guardrail's denial
  # of boundary stripping and IAM user creation. That is weaker than a boundary,
  # since iam:PutRolePolicy on the prefix still allows writing an inline policy
  # wider than the creator holds. It is a deliberate trade against a demo that
  # has to work.
  dynamic "statement" {
    for_each = each.value.require_boundary ? [1] : []

    content {
      sid       = "${each.key}CreateRoleWithBoundary"
      effect    = "Allow"
      actions   = ["iam:CreateRole"]
      resources = each.value.role_arns

      condition {
        test     = "ArnLike"
        variable = "iam:PermissionsBoundary"
        values   = [local.role_boundary_arn_pattern]
      }
    }
  }

  dynamic "statement" {
    for_each = each.value.require_boundary ? [] : [1]

    content {
      sid       = "${each.key}CreateRole"
      effect    = "Allow"
      actions   = ["iam:CreateRole"]
      resources = each.value.role_arns
    }
  }

  dynamic "statement" {
    for_each = length(each.value.passed_to_services) > 0 ? [1] : []

    content {
      sid       = "${each.key}PassRole"
      effect    = "Allow"
      actions   = ["iam:PassRole"]
      resources = each.value.role_arns

      condition {
        test     = "StringEquals"
        variable = "iam:PassedToService"
        values   = each.value.passed_to_services
      }
    }
  }

  dynamic "statement" {
    for_each = length(each.value.service_linked_for) > 0 ? [1] : []

    content {
      sid       = "${each.key}ServiceLinkedRoles"
      effect    = "Allow"
      actions   = ["iam:CreateServiceLinkedRole"]
      resources = ["*"]

      condition {
        test     = "StringEquals"
        variable = "iam:AWSServiceName"
        values   = each.value.service_linked_for
      }
    }
  }
}

# The two statements that were byte-for-byte identical in devops_agent.tf and
# aws_transform.tf. ai_governance.tf keeps its own IamReadOnly: that one adds
# credential reports and the policy simulator, so it is a different grant.
#
# ConsoleBaseline is technically subsumed by iam:List* below it. It is kept as its
# own statement because the reason it exists - the console header cannot render
# the signed-in account without it - is worth stating where someone tempted to
# trim the read block will see it.
data "aws_iam_policy_document" "console_and_iam_read" {
  # Account-wide because terraform refresh resolves AWS managed policies and
  # service roles outside any prefix.
  #
  # iam:List* also covers iam:ListAccountAliases, which the console needs to render
  # the signed-in account in its header. No separate statement for it.
  statement {
    sid       = "IamRead"
    effect    = "Allow"
    actions   = ["iam:Get*", "iam:List*"]
    resources = ["*"]
  }
}
