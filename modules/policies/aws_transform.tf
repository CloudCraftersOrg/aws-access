# Policy document for AWSTransformAccess, the partner demo cohort's set.
#
# Alone in its own file because it is by far the largest document here: it covers
# sign-in to the AWS Transform web app, the legacy fbctf stack the demo
# modernizes, and the two PoC stacks the cohort deploys themselves
# (transform-agents and transform-containers).
#
# local.inline_policies in locals.tf maps each permission set to its document.


# Used by: AWSTransformAccess, the only set allowed outside var.region
# (us-west-2 plus us-east-1, because the partner service is us-east-1 only).
#
# AWS Transform demo cohort: sign in to the web app, deploy the legacy fbctf
# stack the demo modernizes, and run the transform-agents PoC (Bedrock plus
# its own transform-agents-* stack).
#
# The AWSTransform* half is small because the service only authorizes entry to
# its web app with IAM, then hands off to its own workspace roles for everything
# done inside. Work a job performs in the account runs under a service-linked
# role, not the user's session.
#
# The Fbctf* statements exist for the cohort's own `terraform apply`, not for
# anything AWS Transform does.
data "aws_iam_policy_document" "aws_transform_access" {
  # All five role scopes feed this one set: the two AWSTransform service roles, the
  # fbctf demo stack, and the two PoC stacks. All from role_plumbing.tf.
  source_policy_documents = [
    data.aws_iam_policy_document.console_and_iam_read.json,
    data.aws_iam_policy_document.role_plumbing["AWSTransformConnector"].json,
    data.aws_iam_policy_document.role_plumbing["AWSTransformCodeBuild"].json,
    data.aws_iam_policy_document.role_plumbing["Fbctf"].json,
    data.aws_iam_policy_document.role_plumbing["TransformContainer"].json,
    data.aws_iam_policy_document.role_plumbing["TransformAgents"].json,
  ]


  # The whole AWS Transform service: read, profile sign-in, and the write and
  # tagging verbs.
  #
  # transform:* rather than an enumeration, to stay under the 10,240-byte cap on a
  # permission set's inline policy. It is a real widening, and acceptable because
  # operating AWS Transform is this set's entire purpose, the service authorizes
  # only entry to its own web app with IAM and hands off to its own workspace roles
  # for everything done inside, and the set is granted on Sandbox alone.
  statement {
    sid       = "AWSTransformService"
    effect    = "Allow"
    actions   = ["transform:*"]
    resources = ["*"]
  }

  # The console checks account-level public access settings when a connector
  # request is accepted.
  statement {
    sid    = "AWSTransformConnectorPublicAccessCheck"
    effect = "Allow"
    actions = [
      "s3:GetAccountPublicAccessBlock",
      "s3:GetBucketPublicAccessBlock",
    ]
    resources = ["*"]
  }


  statement {
    sid    = "AWSTransformConnectorServiceRole"
    effect = "Allow"
    actions = [
      "iam:AttachRolePolicy",
      "iam:PassRole",
    ]
    resources = ["arn:aws:iam::*:role/service-role/AWSTransform-*"]
  }

  statement {
    sid       = "AWSTransformConnectorServicePolicy"
    effect    = "Allow"
    actions   = ["iam:CreatePolicy"]
    resources = ["arn:aws:iam::*:policy/service-role/AWSTransform-*"]
  }

  # Every service-linked role this set's stacks need, in one path-scoped
  # statement rather than one per service.
  #
  # Safe to widen this way because a service-linked role is not a general-purpose
  # identity. IAM fixes its trust policy to the one service that owns it and
  # refuses arbitrary policy attachments, so this grants the ability to turn
  # services on, not to escalate.
  statement {
    sid       = "ServiceLinkedRoles"
    effect    = "Allow"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["arn:aws:iam::*:role/aws-service-role/*"]
  }

  # Scoped by ViaService rather than by key: the service encrypts with whichever
  # key the profile is configured with, including a customer managed key.
  statement {
    sid    = "AWSTransformKmsViaService"
    effect = "Allow"
    actions = [
      "kms:CreateGrant",
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:RetireGrant",
    ]
    resources = ["*"]

    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["transform.*.amazonaws.com"]
    }
  }

  # AWS Transform Custom (the atx CLI): code transformations and continuous
  # modernization. No resource-level permissions exist for transform-custom, and
  # of this set's two regions it is offered only in us-east-1. Runs bill per
  # agent-minute ($0.035) — hold to `atx --limit` and an account Budgets cap.
  statement {
    sid       = "AWSTransformCustomAgent"
    effect    = "Allow"
    actions   = ["transform-custom:*"]
    resources = ["*"]
  }


  # The whole CodeConnections service, whose only use here is letting AWS Transform
  # reach the cohort's source repository.
  #
  # codeconnections:* rather than an enumeration, under the byte cap. The OAuth
  # handshake verbs cannot be resource-scoped anyway, so the widening is limited to
  # the connection lifecycle.
  statement {
    sid       = "AWSTransformSourceConnections"
    effect    = "Allow"
    actions   = ["codeconnections:*"]
    resources = ["*"]
  }

  # CloudFormation on the service's own stacks. cloudformation:* under the byte
  # cap; the stack name prefix is what contains this, not the verb list.
  statement {
    sid       = "AWSTransformStacks"
    effect    = "Allow"
    actions   = ["cloudformation:*"]
    resources = ["arn:aws:cloudformation:*:*:stack/AWSTransform*/*"]
  }

  # No resource type on any of these. ListStacks is here rather than above
  # because DescribeStacks called without a stack name falls back to it.
  statement {
    sid    = "AWSTransformStacksAccountWide"
    effect = "Allow"
    actions = [
      "cloudformation:CreateUploadBucket",
      "cloudformation:DescribeAccountLimits",
      "cloudformation:GetTemplateSummary",
      "cloudformation:ListStacks",
      "cloudformation:ValidateTemplate",
    ]
    resources = ["*"]
  }


  statement {
    sid    = "AWSTransformCodeBuildExecutionRole"
    effect = "Allow"
    actions = [
      "iam:AttachRolePolicy",
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:DetachRolePolicy",
      "iam:PassRole",
      "iam:PutRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:UpdateRole",
    ]
    resources = [
      "arn:aws:iam::*:role/AWSTransform*",
      "arn:aws:iam::*:role/service-role/AWSTransform*",
    ]
  }

  # The same stack creates six customer managed policies and attaches them to the
  # role above: AWSTransformBasePolicy-<region> plus the Networking, Storage, KMS,
  # ECS and EKS ones. None of them sit under a service-role/ path, so
  # AWSTransformConnectorServicePolicy further up does not reach them.
  #
  # CreatePolicyVersion and SetDefaultPolicyVersion are the redeploy path: a
  # changed policy body becomes a new default version rather than a new policy.
  # Get*/List* are already granted account-wide by FbctfIamRead.
  statement {
    sid    = "AWSTransformCodeBuildPolicies"
    effect = "Allow"
    actions = [
      "iam:CreatePolicy",
      "iam:CreatePolicyVersion",
      "iam:DeletePolicy",
      "iam:DeletePolicyVersion",
      "iam:SetDefaultPolicyVersion",
      "iam:TagPolicy",
      "iam:UntagPolicy",
    ]
    resources = ["arn:aws:iam::*:policy/AWSTransform*"]
  }

  # Service-wide allows are acceptable here: the set is region-locked, granted
  # only to the cohort, and the sensitive edges are prefix-scoped below.
  statement {
    sid    = "FbctfInfraDeploy"
    effect = "Allow"
    actions = [
      "autoscaling:*",
      "cloudwatch:*",
      "ec2:*",
      "elasticache:*",
      "elasticloadbalancing:*",
      "kms:DescribeKey",
      "kms:ListAliases",
      "logs:*",
      "rds:*",
      "ssm:*",
    ]
    resources = ["*"]
  }

  statement {
    sid     = "FbctfS3"
    effect  = "Allow"
    actions = ["s3:*"]
    resources = [
      "arn:aws:s3:::${var.demo_app_prefix}-*",
      "arn:aws:s3:::${var.demo_app_prefix}-*/*",
    ]
  }

  statement {
    sid    = "FbctfIamWriteScoped"
    effect = "Allow"
    actions = [
      "iam:AddRoleToInstanceProfile",
      "iam:AttachRolePolicy",
      "iam:CreateInstanceProfile",
      "iam:DeleteInstanceProfile",
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:DetachRolePolicy",
      "iam:PutRolePolicy",
      "iam:RemoveRoleFromInstanceProfile",
      "iam:TagInstanceProfile",
      "iam:TagRole",
      "iam:UntagInstanceProfile",
      "iam:UntagRole",
    ]
    resources = [
      "arn:aws:iam::*:role/${var.demo_app_prefix}-*",
      "arn:aws:iam::*:instance-profile/${var.demo_app_prefix}-*",
    ]
  }




  # rds!* covers the master secret RDS creates when it manages the password.
  statement {
    sid     = "FbctfSecrets"
    effect  = "Allow"
    actions = ["secretsmanager:*"]
    resources = [
      "arn:aws:secretsmanager:*:*:secret:${var.demo_app_prefix}-*",
      "arn:aws:secretsmanager:*:*:secret:rds!*",
    ]
  }

  # transform-containers PoC. Enumerated verbs on purpose: iam:* on a role name
  # would cover CreateRole, UpdateAssumeRolePolicy and AttachRolePolicy with no
  # condition on any of them, which is the most direct escalation path there is.
  #
  # CreateRole and PassRole come from role_plumbing.tf, with PassRole limited to
  # ECS. If the PoC passes its task role to something else, add that service to the
  # TransformContainer scope there; it fails with an explicit deny, not silently.
  statement {
    sid       = "TransformContainerSecrets"
    effect    = "Allow"
    actions   = ["secretsmanager:*"]
    resources = ["arn:aws:secretsmanager:*:*:secret:${var.transform_container_prefix}-*"]
  }

  statement {
    sid    = "TransformContainerRoles"
    effect = "Allow"
    actions = [
      "iam:AttachRolePolicy",
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:DetachRolePolicy",
      "iam:PutRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:UpdateRole",
      "iam:UpdateRoleDescription",
    ]
    resources = ["arn:aws:iam::*:role/${var.transform_container_prefix}-*"]
  }

  # S3 for the containers PoC ALB logs bucket (tcpoc-* prefix).
  statement {
    sid     = "TransformContainerS3"
    effect  = "Allow"
    actions = ["s3:*"]
    resources = [
      "arn:aws:s3:::*poc-*",
      "arn:aws:s3:::*poc-*/*",
    ]
  }

  # Bedrock for the transform-agents PoC. bedrock:* under the byte cap, and the
  # widest of the collapses in this file: it covers model management and the rest
  # of the control plane, not just guardrails and inference. What contains it is
  # the region lockdown and the fact that this set is granted on Sandbox only.
  statement {
    sid       = "TransformAgentsBedrock"
    effect    = "Allow"
    actions   = ["bedrock:*"]
    resources = ["*"]
  }

  # Service-wide: AgentCore ARNs share no prefix. Contained by the region
  # lockdown and the cohort-only grant, as with transform-custom:* above.
  statement {
    sid       = "TransformAgentsAgentCore"
    effect    = "Allow"
    actions   = ["bedrock-agentcore:*"]
    resources = ["*"]
  }

  # Read-only, plus InitializeService to turn the service on.
  #
  # Wildcards rather than an enumeration: every mgn Describe*/Get*/List* action
  # is classified Read or List in the service authorization reference, so these
  # cannot reach a write verb. The list they replace named only DescribeJobs,
  # DescribeReplicationConfigurationTemplates, DescribeSourceServers,
  # DescribeVcenterClients, GetLaunchConfiguration and ListTagsForResource,
  # which is narrower than the console needs: rendering the vCenter clients and
  # source server pages also calls GetAccountSettings, ListConnectors,
  # ListApplications and ListWaves, and each one failed on its own denial.
  #
  # Wave mutations still run under the step-dispatcher Lambda's role.
  statement {
    sid    = "TransformAgentsMgnRead"
    effect = "Allow"
    actions = [
      "mgn:Describe*",
      "mgn:Get*",
      "mgn:InitializeService",
      "mgn:List*",
      "mgn:Create*"
    ]
    resources = ["*"]
  }

  # mgn:InitializeService creates the AWSApplicationMigration* roles and their
  # instance profiles on first use. Scoped by name, like AWSTransformConnectorServiceRole.
  statement {
    sid    = "MgnBootstrapRoles"
    effect = "Allow"
    actions = [
      "iam:AddRoleToInstanceProfile",
      "iam:AttachRolePolicy",
      "iam:CreateInstanceProfile",
      "iam:CreateRole",
      "iam:PassRole",
      "iam:PutRolePolicy",
      "iam:TagInstanceProfile",
      "iam:TagRole",
    ]
    resources = [
      "arn:aws:iam::*:instance-profile/AWSApplicationMigration*",
      "arn:aws:iam::*:role/AWSApplicationMigration*",
      "arn:aws:iam::*:role/service-role/AWSApplicationMigration*",
    ]
  }

  # Collapsed from an enumeration to service:* on the same prefix-scoped
  # resource, to stay under the 10,240 non-whitespace byte cap on a permission
  # set inline policy. Same trade already made by FbctfS3, FbctfSecrets and
  # TransformAgentsVectorStore: the prefix, not the verb list, is what contains
  # these. Re-enumerating any of them costs roughly 400-550 bytes of budget.
  statement {
    sid       = "TransformAgentsTables"
    effect    = "Allow"
    actions   = ["dynamodb:*"]
    resources = ["arn:aws:dynamodb:*:*:table/${var.transform_agents_prefix}-*"]
  }

  statement {
    sid       = "TransformAgentsListTables"
    effect    = "Allow"
    actions   = ["dynamodb:ListTables"]
    resources = ["*"]
  }

  statement {
    sid       = "TransformAgentsLambda"
    effect    = "Allow"
    actions   = ["lambda:*"]
    resources = ["arn:aws:lambda:*:*:function:${var.transform_agents_prefix}-*"]
  }

  statement {
    sid    = "TransformAgentsSchedule"
    effect = "Allow"
    actions = [
      "scheduler:CreateSchedule",
      "scheduler:DeleteSchedule",
      "scheduler:GetSchedule",
      "scheduler:ListSchedules",
      "scheduler:TagResource",
      "scheduler:UntagResource",
      "scheduler:UpdateSchedule",
    ]
    resources = ["arn:aws:scheduler:*:*:schedule/*/${var.transform_agents_prefix}-*"]
  }

  statement {
    sid       = "TransformAgentsEcrAuth"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid       = "TransformAgentsEcr"
    effect    = "Allow"
    actions   = ["ecr:*"]
    resources = ["arn:aws:ecr:*:*:repository/${var.transform_agents_prefix}-*"]
  }

  statement {
    sid     = "TransformAgentsBuckets"
    effect  = "Allow"
    actions = ["s3:*"]
    resources = [
      "arn:aws:s3:::${var.transform_agents_prefix}-*",
      "arn:aws:s3:::${var.transform_agents_prefix}-*/*",
    ]
  }

  # Runbook knowledge base. No resource-level actions published yet.
  statement {
    sid     = "TransformAgentsVectorStore"
    effect  = "Allow"
    actions = ["s3vectors:*"]
    resources = [
      "arn:aws:s3vectors:*:*:bucket/${var.transform_agents_prefix}-*",
      "arn:aws:s3vectors:*:*:bucket/${var.transform_agents_prefix}-*/*",
    ]
  }

  statement {
    sid    = "TransformAgentsBudget"
    effect = "Allow"
    actions = [
      "budgets:CreateBudget",
      "budgets:DeleteBudget",
      "budgets:DescribeBudget",
      "budgets:ListTagsForResource",
      "budgets:ModifyBudget",
      "budgets:ViewBudget",
    ]
    resources = ["arn:aws:budgets::*:budget/${var.transform_agents_prefix}-*"]
  }

  # The runtime and step-dispatcher roles, path-scoped like FbctfIamWriteScoped.
  statement {
    sid    = "TransformAgentsRoles"
    effect = "Allow"
    actions = [
      "iam:AttachRolePolicy",
      "iam:CreatePolicy",
      "iam:CreatePolicyVersion",
      "iam:CreateRole",
      "iam:DeletePolicy",
      "iam:DeletePolicyVersion",
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:DetachRolePolicy",
      "iam:PutRolePolicy",
      "iam:TagPolicy",
      "iam:TagRole",
      "iam:UntagPolicy",
      "iam:UntagRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:UpdateRole",
      "iam:UpdateRoleDescription",
    ]
    resources = [
      "arn:aws:iam::*:policy/${var.transform_agents_prefix}-*",
      "arn:aws:iam::*:role/${var.transform_agents_prefix}-*",
    ]
  }
}
