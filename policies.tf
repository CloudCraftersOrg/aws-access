# IAM policy documents behind the permission sets, plus the region lockdown that
# is merged into every one of them.
#
# WHICH POLICY BACKS WHICH PERMISSION SET
#
#   Permission set        Backed by                        Defined in
#   -------------------   ------------------------------   -------------
#   AdministratorAccess   AWS managed AdministratorAccess  variables.tf
#   ReadOnlyAccess        AWS managed ReadOnlyAccess       variables.tf
#   PowerUserAccess       power_user_access                this file
#   WorkshopOnlyAccess    infra_modify_only                this file
#   DevOpsAgentAccess     devops_agent_access              this file
#   AWSTransformAccess    partner_demo_access              this file
#   AIGovernance          ai_governance                    this file
#
# Read that table rather than trusting the names. They do not line up: the keys
# here are snake_case while the sets are PascalCase, `PowerUserAccess` is a
# read-only set and is not the AWS managed policy of the same name, and
# `WorkshopOnlyAccess` is backed by something called `infra_modify_only`.
#
# HOW THE LINK IS MADE
#
# No resource in this file names a permission set. The connection is assembled
# across three files, which is why the table above is worth keeping accurate:
#
#   1. variables.tf        permission_sets["WorkshopOnlyAccess"]
#                            .inline_policy_key = "infra_modify_only"
#
#   2. policies.tf         local.inline_policies["infra_modify_only"]
#                            = data.aws_iam_policy_document.infra_modify_only
#
#   3. permission_sets.tf  that document, merged with
#                          region_restriction["WorkshopOnlyAccess"], becomes the
#                          set's single inline policy
#
# The indirection exists so two permission sets can share one document. Nothing
# does today, so the mapping is 1:1.
#
# Every set gets `region_restriction` merged in, including the two that carry an
# AWS managed policy — so a managed policy is still capped to its set's regions.
#
# To add a document: define it here, register it in local.inline_policies below,
# add its key to the inline_policy_key validation in variables.tf, then set
# inline_policy_key on a permission set.

# inline_policy_key (as used in variables.tf) => policy JSON.
# The trailing comment on each line is the permission set that consumes it.
locals {
  inline_policies = {
    power_user_access   = data.aws_iam_policy_document.power_user_access.json   # PowerUserAccess
    infra_modify_only   = data.aws_iam_policy_document.infra_modify_only.json   # WorkshopOnlyAccess
    devops_agent_access = data.aws_iam_policy_document.devops_agent_access.json # DevOpsAgentAccess
    partner_demo_access = data.aws_iam_policy_document.partner_demo_access.json # AWSTransformAccess
    ai_governance       = data.aws_iam_policy_document.ai_governance.json       # AIGovernance
  }
}

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

# Used by: PowerUserAccess.
#
# Despite that permission set name, this is NOT the AWS managed PowerUserAccess
# policy. It is a read-only observer set. InvokeAgentRuntime is the only
# non-read action, for running demos from a local machine.
data "aws_iam_policy_document" "power_user_access" {
  statement {
    sid    = "AgentCoreReadOnly"
    effect = "Allow"
    actions = [
      "bedrock-agentcore:Get*",
      "bedrock-agentcore:List*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "InvokeAgentRuntime"
    effect = "Allow"
    actions = [
      "bedrock-agentcore:InvokeAgentRuntime",
    ]
    resources = ["*"]
  }

  # No InvokeModel: direct model calls are made by the runtime's own role.
  statement {
    sid    = "BedrockReadOnly"
    effect = "Allow"
    actions = [
      "bedrock:Get*",
      "bedrock:List*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "CloudWatchReadOnly"
    effect = "Allow"
    actions = [
      "cloudwatch:Describe*",
      "cloudwatch:Get*",
      "cloudwatch:List*",
    ]
    resources = ["*"]
  }

  # Query and Live Tail are read-only data access. No group creation, deletion
  # or retention changes.
  statement {
    sid    = "LogsReadOnly"
    effect = "Allow"
    actions = [
      "logs:Describe*",
      "logs:FilterLogEvents",
      "logs:Get*",
      "logs:List*",
      "logs:StartLiveTail",
      "logs:StartQuery",
      "logs:StopLiveTail",
      "logs:StopQuery",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "XRayReadOnly"
    effect = "Allow"
    actions = [
      "xray:BatchGet*",
      "xray:Get*",
      "xray:List*",
    ]
    resources = ["*"]
  }

  # No grafana:*: token minting and workspace admin stay with the runtime role.
  statement {
    sid    = "GrafanaReadOnly"
    effect = "Allow"
    actions = [
      "grafana:Describe*",
      "grafana:List*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ResourceDiscoveryReadOnly"
    effect = "Allow"
    actions = [
      "ec2:Describe*",
      "lambda:Get*",
      "lambda:List*",
      "rds:Describe*",
      "rds:List*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "EcrReadOnly"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:Describe*",
      "ecr:Get*",
      "ecr:List*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "CloudTrailReadOnly"
    effect = "Allow"
    actions = [
      "cloudtrail:Describe*",
      "cloudtrail:Get*",
      "cloudtrail:List*",
      "cloudtrail:LookupEvents",
    ]
    resources = ["*"]
  }

  # Get* covers GetJob, whose response carries the build and deploy log URLs.
  # No Start/Create/Update, so this grants log visibility without the ability
  # to deploy.
  statement {
    sid    = "AmplifyReadOnly"
    effect = "Allow"
    actions = [
      "amplify:Get*",
      "amplify:List*",
    ]
    resources = ["*"]
  }
}

# Used by: WorkshopOnlyAccess.
#
# Read plus update/tag on workshop services, no create or destroy. Enough to
# run `terraform apply` against resources that already exist. The explicit
# DenyCreateAndDestroy statement below beats any Allow added above it.
data "aws_iam_policy_document" "infra_modify_only" {
  # Wide enough for `terraform plan` to refresh state.
  statement {
    sid    = "WorkshopReadOnly"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:Describe*",
      "ecr:Get*",
      "ecr:List*",
      "iam:Get*",
      "iam:List*",
      "logs:Describe*",
      "logs:FilterLogEvents",
      "logs:Get*",
      "logs:List*",
      "logs:StartLiveTail",
      "logs:StopLiveTail",
      "bedrock:Get*",
      "bedrock:List*",
      "bedrock:Retrieve",
      "bedrock:RetrieveAndGenerate",
      "bedrock-agentcore:Get*",
      "bedrock-agentcore:List*",
      "aoss:BatchGet*",
      "aoss:Get*",
      "aoss:List*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "WorkshopModifyOnly"
    effect = "Allow"
    actions = [
      "ecr:CompleteLayerUpload",
      "ecr:GetAuthorizationToken",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:PutLifecyclePolicy",
      "ecr:SetRepositoryPolicy",
      "ecr:TagResource",
      "ecr:UntagResource",
      "ecr:UploadLayerPart",

      # PassRole is needed for apply.
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:PassRole",
      "iam:PutRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:UpdateRole",
      "iam:UpdateRoleDescription",

      "logs:PutRetentionPolicy",
      "logs:TagResource",
      "logs:UntagResource",

      "bedrock-agentcore:TagResource",
      "bedrock-agentcore:UntagResource",
      "bedrock-agentcore:UpdateAgentRuntime",
      "bedrock-agentcore:UpdateAgentRuntimeEndpoint",
      "bedrock-agentcore:UpdateMemory",

      "bedrock:TagResource",
      "bedrock:UntagResource",
      "bedrock:UpdateDataSource",
      "bedrock:UpdateKnowledgeBase",

      "aoss:APIAccessAll",
      "aoss:DashboardsAccessAll",
      "aoss:TagResource",
      "aoss:UntagResource",
      "aoss:UpdateAccessPolicy",
      "aoss:UpdateCollection",
      "aoss:UpdateLifecyclePolicy",
      "aoss:UpdateSecurityPolicy",
    ]
    resources = ["*"]
  }

  # Belt and suspenders: an accidentally-widened Allow above still cannot
  # create or destroy.
  statement {
    sid    = "DenyCreateAndDestroy"
    effect = "Deny"
    actions = [
      "ecr:CreateRepository",
      "ecr:DeleteLifecyclePolicy",
      "ecr:DeleteRepository",
      "ecr:DeleteRepositoryPolicy",
      "iam:CreatePolicy",
      "iam:CreateRole",
      "iam:CreateServiceLinkedRole",
      "iam:DeletePolicy",
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:DeleteServiceLinkedRole",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:DeleteLogGroup",
      "logs:DeleteLogStream",
      "logs:DeleteRetentionPolicy",
      "bedrock-agentcore:CreateAgentRuntime",
      "bedrock-agentcore:CreateAgentRuntimeEndpoint",
      "bedrock-agentcore:CreateMemory",
      "bedrock-agentcore:DeleteAgentRuntime",
      "bedrock-agentcore:DeleteAgentRuntimeEndpoint",
      "bedrock-agentcore:DeleteMemory",
      "bedrock:CreateDataSource",
      "bedrock:CreateKnowledgeBase",
      "bedrock:DeleteDataSource",
      "bedrock:DeleteKnowledgeBase",
      "aoss:CreateAccessPolicy",
      "aoss:CreateCollection",
      "aoss:CreateLifecyclePolicy",
      "aoss:CreateSecurityPolicy",
      "aoss:DeleteAccessPolicy",
      "aoss:DeleteCollection",
      "aoss:DeleteLifecyclePolicy",
      "aoss:DeleteSecurityPolicy",
    ]
    resources = ["*"]
  }

  # Omitted entirely when no buckets are configured.
  dynamic "statement" {
    for_each = length(var.state_bucket_names) > 0 ? [1] : []

    content {
      sid    = "TerraformStateAccess"
      effect = "Allow"
      actions = [
        "s3:GetBucketLocation",
        "s3:GetBucketVersioning",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:PutObject",
      ]
      resources = flatten([
        for bucket in var.state_bucket_names : [
          "arn:aws:s3:::${bucket}",
          "arn:aws:s3:::${bucket}/*",
        ]
      ])
    }
  }

  statement {
    sid    = "InvokeAgentRuntime"
    effect = "Allow"
    actions = [
      "bedrock-agentcore:InvokeAgentRuntime",
    ]
    resources = ["*"]
  }
}

# Used by: DevOpsAgentAccess.
#
# Deploys and diagnoses the common services used by the initial DevOps Agent
# PoC: EC2/VPC, ECR, ECS, EKS, load balancers, autoscaling, RDS, and the
# Lambda/SNS/SQS/CloudWatch plumbing around them.
#
# us-east-1 is included for the public DevOps Agent samples; us-west-2 remains
# allowed as the organization's default region. Sensitive write paths stay
# scoped to demo-* and devops-agent-* names.
data "aws_iam_policy_document" "devops_agent_access" {
  statement {
    sid    = "ConsoleBaseline"
    effect = "Allow"
    actions = [
      "iam:ListAccountAliases",
    ]
    resources = ["*"]
  }

  # DevOps Agent IAM actions use the aidevops prefix.
  statement {
    sid       = "DevOpsAgentControlPlane"
    effect    = "Allow"
    actions   = ["aidevops:*"]
    resources = ["*"]
  }

  statement {
    sid    = "InfrastructureDiagnosisReadOnly"
    effect = "Allow"
    actions = [
      "autoscaling:Describe*",
      "cloudformation:Describe*",
      "cloudformation:Get*",
      "cloudformation:List*",
      "cloudtrail:Describe*",
      "cloudtrail:Get*",
      "cloudtrail:List*",
      "cloudtrail:LookupEvents",
      "cloudwatch:Describe*",
      "cloudwatch:Get*",
      "cloudwatch:List*",
      "dynamodb:Describe*",
      "dynamodb:List*",
      "ec2:Describe*",
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:Describe*",
      "ecr:Get*",
      "ecr:List*",
      "ecs:Describe*",
      "ecs:List*",
      "eks:Describe*",
      "eks:List*",
      "elasticloadbalancing:Describe*",
      "events:Describe*",
      "events:List*",
      "events:TestEventPattern",
      "iam:Get*",
      "iam:List*",
      "iam:SimulateCustomPolicy",
      "iam:SimulatePrincipalPolicy",
      "kms:Describe*",
      "kms:Get*",
      "kms:List*",
      "lambda:Get*",
      "lambda:List*",
      "logs:Describe*",
      "logs:FilterLogEvents",
      "logs:Get*",
      "logs:List*",
      "logs:StartLiveTail",
      "logs:StartQuery",
      "logs:StopLiveTail",
      "logs:StopQuery",
      "rds:Describe*",
      "rds:List*",
      "resourcegroupstaggingapi:GetResources",
      "resourcegroupstaggingapi:GetTagKeys",
      "resourcegroupstaggingapi:GetTagValues",
      "route53:Get*",
      "route53:List*",
      "route53:TestDNSAnswer",
      "route53resolver:Get*",
      "route53resolver:List*",
      "s3:GetAccountPublicAccessBlock",
      "s3:GetBucket*",
      "s3:ListAllMyBuckets",
      "s3:ListBucket",
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetResourcePolicy",
      "secretsmanager:ListSecrets",
      "sns:Get*",
      "sns:List*",
      "sqs:GetQueue*",
      "sqs:ListQueues",
      "ssm:Describe*",
      "ssm:List*",
      "xray:BatchGet*",
      "xray:Get*",
      "xray:List*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DevOpsAgentCloudFormationWrite"
    effect = "Allow"
    actions = [
      "cloudformation:CreateChangeSet",
      "cloudformation:CreateStack",
      "cloudformation:DeleteChangeSet",
      "cloudformation:DeleteStack",
      "cloudformation:ExecuteChangeSet",
      "cloudformation:UpdateStack",
      "cloudformation:ValidateTemplate",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DevOpsAgentAlarmAndKmsWrite"
    effect = "Allow"
    actions = [
      "cloudwatch:DeleteAlarms",
      "cloudwatch:PutMetricAlarm",
      "cloudwatch:TagResource",
      "cloudwatch:UntagResource",

      "kms:CancelKeyDeletion",
      "kms:CreateKey",
      "kms:DisableKeyRotation",
      "kms:EnableKeyRotation",
      "kms:GetKeyPolicy",
      "kms:PutKeyPolicy",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
      "kms:UntagResource",
    ]
    resources = ["*"]
  }

  # Common deploy/write path for the first PoC.
  statement {
    sid    = "DevOpsAgentInfraDeploy"
    effect = "Allow"
    actions = [
      "application-autoscaling:*",
      "autoscaling:*",
      "dynamodb:CreateTable",
      "dynamodb:DeleteTable",
      "dynamodb:TagResource",
      "dynamodb:UntagResource",
      "dynamodb:UpdateContinuousBackups",
      "dynamodb:UpdateTable",

      "ec2:*",
      "ecr:*",
      "ecs:*",
      "eks:*",
      "elasticloadbalancing:*",

      "events:DeleteRule",
      "events:DisableRule",
      "events:EnableRule",
      "events:PutRule",
      "events:PutTargets",
      "events:RemoveTargets",
      "events:TagResource",
      "events:UntagResource",

      "lambda:CreateFunction",
      "lambda:AddPermission",
      "lambda:DeleteFunction",
      "lambda:InvokeFunction",
      "lambda:RemovePermission",
      "lambda:TagResource",
      "lambda:UntagResource",
      "lambda:UpdateFunctionCode",
      "lambda:UpdateFunctionConfiguration",

      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:DeleteLogGroup",
      "logs:DeleteLogStream",
      "logs:DeleteMetricFilter",
      "logs:DeleteRetentionPolicy",
      "logs:DeleteSubscriptionFilter",
      "logs:PutMetricFilter",
      "logs:PutRetentionPolicy",
      "logs:PutSubscriptionFilter",
      "logs:TagLogGroup",
      "logs:UntagLogGroup",

      "rds:*",
      "servicediscovery:*",

      "sns:CreateTopic",
      "sns:DeleteTopic",
      "sns:Publish",
      "sns:SetTopicAttributes",
      "sns:Subscribe",
      "sns:TagResource",
      "sns:Unsubscribe",
      "sns:UntagResource",

      "sqs:CreateQueue",
      "sqs:DeleteQueue",
      "sqs:PurgeQueue",
      "sqs:SendMessage",
      "sqs:SetQueueAttributes",
      "sqs:TagQueue",
      "sqs:UntagQueue",

      "ssm:*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DevOpsAgentS3Scoped"
    effect = "Allow"
    actions = [
      "s3:CreateBucket",
      "s3:DeleteBucket",
      "s3:DeleteBucketPolicy",
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
      "s3:GetBucketLocation",
      "s3:GetBucketVersioning",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketVersions",
      "s3:PutBucketEncryption",
      "s3:PutBucketPolicy",
      "s3:PutBucketPublicAccessBlock",
      "s3:PutBucketVersioning",
      "s3:PutObject",
    ]
    resources = [
      "arn:aws:s3:::demo-*",
      "arn:aws:s3:::demo-*/*",
      "arn:aws:s3:::devops-agent-*",
      "arn:aws:s3:::devops-agent-*/*",
    ]
  }

  statement {
    sid    = "DevOpsAgentSecretsScoped"
    effect = "Allow"
    actions = [
      "secretsmanager:CreateSecret",
      "secretsmanager:DeleteSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:RestoreSecret",
      "secretsmanager:TagResource",
      "secretsmanager:UntagResource",
      "secretsmanager:UpdateSecret",
    ]
    resources = [
      "arn:aws:secretsmanager:*:*:secret:demo-*",
      "arn:aws:secretsmanager:*:*:secret:devops-agent-*",
      "arn:aws:secretsmanager:*:*:secret:rds!*",
    ]
  }

  statement {
    sid       = "DevOpsAgentIamRead"
    effect    = "Allow"
    actions   = ["iam:Get*", "iam:List*"]
    resources = ["*"]
  }

  statement {
    sid    = "DevOpsAgentIamWriteScoped"
    effect = "Allow"
    actions = [
      "iam:AddRoleToInstanceProfile",
      "iam:AttachRolePolicy",
      "iam:CreateInstanceProfile",
      "iam:CreatePolicy",
      "iam:CreateRole",
      "iam:DeleteInstanceProfile",
      "iam:DeletePolicy",
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:DetachRolePolicy",
      "iam:PutRolePolicy",
      "iam:RemoveRoleFromInstanceProfile",
      "iam:TagInstanceProfile",
      "iam:TagPolicy",
      "iam:TagRole",
      "iam:UntagInstanceProfile",
      "iam:UntagPolicy",
      "iam:UntagRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:UpdateRole",
      "iam:UpdateRoleDescription",
    ]
    resources = [
      "arn:aws:iam::*:instance-profile/demo-*",
      "arn:aws:iam::*:instance-profile/devops-agent-*",
      "arn:aws:iam::*:policy/demo-*",
      "arn:aws:iam::*:policy/devops-agent-*",
      "arn:aws:iam::*:role/demo-*",
      "arn:aws:iam::*:role/devops-agent-*",
    ]
  }

  statement {
    sid     = "DevOpsAgentIamPassRole"
    effect  = "Allow"
    actions = ["iam:PassRole"]
    resources = [
      "arn:aws:iam::*:role/demo-*",
      "arn:aws:iam::*:role/devops-agent-*",
    ]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values = [
        "ec2.amazonaws.com",
        "ecs-tasks.amazonaws.com",
        "eks.amazonaws.com",
        "lambda.amazonaws.com",
        "monitoring.rds.amazonaws.com",
      ]
    }
  }

  statement {
    sid       = "DevOpsAgentServiceLinkedRoles"
    effect    = "Allow"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values = [
        "autoscaling.amazonaws.com",
        "ecs.amazonaws.com",
        "eks.amazonaws.com",
        "elasticloadbalancing.amazonaws.com",
        "rds.amazonaws.com",
      ]
    }
  }
}

# Used by: AWSTransformAccess, the only set allowed outside var.region
# (us-west-2 plus us-east-1, because the partner service is us-east-1 only).
#
# AWS Transform demo cohort: sign in to the web app, plus deploy the legacy
# fbctf stack the demo modernizes.
#
# The AWSTransform* half is small because the service only authorizes entry to
# its web app with IAM, then hands off to its own workspace roles for everything
# done inside. Work a job performs in the account runs under a service-linked
# role, not the user's session.
#
# The Fbctf* statements exist for the cohort's own `terraform apply`, not for
# anything AWS Transform does.
data "aws_iam_policy_document" "partner_demo_access" {
  # Without this the console header cannot render the signed-in account.
  statement {
    sid    = "ConsoleBaseline"
    effect = "Allow"
    actions = [
      "iam:ListAccountAliases",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AWSTransformReadOnly"
    effect = "Allow"
    actions = [
      "transform:Get*",
      "transform:List*",
    ]
    resources = ["*"]
  }

  # Classified as a Write action, so it is not covered by Get*/List* above.
  # Without it a user sees the profile and is still refused at sign-in.
  #
  # Account is a wildcard because this permission set is provisioned into more
  # than one account. Profile is a wildcard because it is created when the
  # service is first enabled, so the ID is unknown at plan time.
  statement {
    sid    = "AWSTransformWebAppAccess"
    effect = "Allow"
    actions = [
      "transform:AccessTransformProfile",
    ]
    resources = ["arn:aws:transform:${var.demo_app_region}:*:profile/*"]
  }

  # Write and Tagging verbs only: the Get*/List* counterparts are already
  # covered by AWSTransformReadOnly above.
  #
  # This does not affect what a user can do *inside* a workspace — that is
  # governed by AWS Transform workspace roles, which are not IAM.
  statement {
    sid    = "AWSTransformAdministration"
    effect = "Allow"
    actions = [
      "transform:AssociateConnectorResource",
      "transform:CreateProfile",
      "transform:DeleteConnector",
      "transform:DeleteProfile",
      "transform:PutAgentRuntimeConfiguration",
      "transform:RejectConnector",
      "transform:TagResource",
      "transform:UntagResource",
      "transform:UpdateAccountSettings",
      "transform:UpdateAgentAccess",
      "transform:UpdateProfile",
    ]
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

  # Accepting a connector request creates a service role for it. Path-scoped to
  # AWSTransform-*, so this does not widen the fbctf-* IAM scope below.
  statement {
    sid    = "AWSTransformConnectorServiceRole"
    effect = "Allow"
    actions = [
      "iam:AttachRolePolicy",
      "iam:CreateRole",
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

  # Created on first enable, so the service cannot be turned on without it.
  statement {
    sid       = "AWSTransformServiceLinkedRole"
    effect    = "Allow"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["arn:aws:iam::*:role/aws-service-role/transform.amazonaws.com/AWSServiceRoleForAWSTransform"]
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

  statement {
    sid       = "AWSTransformCustomServiceLinkedRole"
    effect    = "Allow"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["arn:aws:iam::*:role/aws-service-role/transform-custom.amazonaws.com/AWSServiceRoleForAWSTransformCustom"]

    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values   = ["transform-custom.amazonaws.com"]
    }
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

  # Reads are account-wide because terraform refresh resolves AWS managed
  # policies and service roles outside the prefix.
  statement {
    sid       = "FbctfIamRead"
    effect    = "Allow"
    actions   = ["iam:Get*", "iam:List*"]
    resources = ["*"]
  }

  statement {
    sid    = "FbctfIamWriteScoped"
    effect = "Allow"
    actions = [
      "iam:AddRoleToInstanceProfile",
      "iam:AttachRolePolicy",
      "iam:CreateInstanceProfile",
      "iam:CreateRole",
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

  statement {
    sid       = "FbctfIamPassRole"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::*:role/${var.demo_app_prefix}-*"]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ec2.amazonaws.com"]
    }
  }

  # The first apply in a fresh account creates these.
  statement {
    sid       = "FbctfServiceLinkedRoles"
    effect    = "Allow"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values = [
        "autoscaling.amazonaws.com",
        "elasticache.amazonaws.com",
        "elasticloadbalancing.amazonaws.com",
        "rds.amazonaws.com",
      ]
    }
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
}

# Used by: AIGovernance.
#
# The AI governance operator: inventory every AI service, invoke and evaluate
# Bedrock models to validate the controls, enforce those controls at account and
# organization level (guardrails, invocation logging, Config rules, SCPs, Audit
# Manager), and produce the audit evidence. Read is account-wide; provisioning
# write is confined to the controls and to AIGovernance-* / aigov-* resources.
#
# organizations:* write only functions from the management or a delegated-admin
# account - see the AIGovernance grant. bedrock:InvokeModel is granted (the wider
# AI services' inference verbs are not): the operator runs Bedrock to red-team
# its own guardrails, accepting that those calls land in the trail it audits.
data "aws_iam_policy_document" "ai_governance" {
  statement {
    sid    = "AiServiceInventoryReadOnly"
    effect = "Allow"
    actions = [
      "bedrock-agentcore:Get*",
      "bedrock-agentcore:List*",
      "bedrock:Get*",
      "bedrock:List*",
      "comprehend:Describe*",
      "comprehend:List*",
      "comprehendmedical:Describe*",
      "comprehendmedical:List*",
      "forecast:Describe*",
      "forecast:List*",
      "frauddetector:BatchGet*",
      "frauddetector:Describe*",
      "frauddetector:Get*",
      "kendra:Describe*",
      "kendra:List*",
      "lex:Describe*",
      "lex:List*",
      "lexv2-models:Describe*",
      "lexv2-models:List*",
      "lookoutequipment:Describe*",
      "lookoutequipment:List*",
      "lookoutmetrics:Describe*",
      "lookoutmetrics:Get*",
      "lookoutmetrics:List*",
      "lookoutvision:Describe*",
      "lookoutvision:List*",
      "personalize:Describe*",
      "personalize:List*",
      "polly:Describe*",
      "polly:List*",
      "qapps:Get*",
      "qapps:List*",
      "qbusiness:Get*",
      "qbusiness:List*",
      "rekognition:Describe*",
      "rekognition:List*",
      "sagemaker:Describe*",
      "sagemaker:List*",
      "transcribe:Get*",
      "transcribe:List*",
      "translate:Describe*",
      "translate:Get*",
      "translate:List*",
    ]
    resources = ["*"]
  }

  # Invoke Bedrock to test guardrails end to end and run evaluation / batch
  # jobs for automated governance checks. The wider AI services' own inference
  # verbs (comprehend:DetectSentiment, rekognition:DetectLabels, ...) stay out.
  statement {
    sid    = "BedrockInvokeAndEvaluate"
    effect = "Allow"
    actions = [
      "bedrock-agentcore:InvokeAgentRuntime",
      "bedrock:Converse",
      "bedrock:ConverseStream",
      "bedrock:CreateEvaluationJob",
      "bedrock:CreateModelInvocationJob",
      "bedrock:InvokeAgent",
      "bedrock:InvokeFlow",
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream",
      "bedrock:Retrieve",
      "bedrock:RetrieveAndGenerate",
      "bedrock:StopEvaluationJob",
      "bedrock:StopModelInvocationJob",
    ]
    resources = ["*"]
  }

  # Cross-service resource discovery so the inventory above can be reconciled
  # against what is actually tagged and deployed.
  statement {
    sid    = "ResourceInventoryReadOnly"
    effect = "Allow"
    actions = [
      "resource-explorer-2:BatchGetView",
      "resource-explorer-2:Get*",
      "resource-explorer-2:List*",
      "resource-explorer-2:Search",
      "tag:Describe*",
      "tag:Get*",
    ]
    resources = ["*"]
  }

  # ApplyGuardrail evaluates sample text against a guardrail before it is
  # enforced and never reaches a model. TagResource lets the operator label
  # the guardrails it creates for lifecycle and ownership.
  statement {
    sid    = "GuardrailManagement"
    effect = "Allow"
    actions = [
      "bedrock:ApplyGuardrail",
      "bedrock:CreateGuardrail",
      "bedrock:CreateGuardrailVersion",
      "bedrock:DeleteGuardrail",
      "bedrock:TagResource",
      "bedrock:UntagResource",
      "bedrock:UpdateGuardrail",
    ]
    resources = ["*"]
  }

  # Turning model-invocation logging on is what makes usage auditable at all.
  # The Put call validates its destination, so the operator also needs to build
  # that destination: the delivery role, the log group, and the S3 bucket.
  statement {
    sid    = "ModelInvocationLoggingControl"
    effect = "Allow"
    actions = [
      "bedrock:DeleteModelInvocationLoggingConfiguration",
      "bedrock:PutModelInvocationLoggingConfiguration",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "InvocationLoggingLogGroup"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:DeleteLogGroup",
      "logs:PutRetentionPolicy",
      "logs:PutResourcePolicy",
      "logs:TagLogGroup",
      "logs:TagResource",
      "logs:UntagLogGroup",
      "logs:UntagResource",
    ]
    resources = [
      "arn:aws:logs:*:*:log-group:/aws/bedrock/*",
      "arn:aws:logs:*:*:log-group:/aws/vendedlogs/bedrock/*",
      "arn:aws:logs:*:*:log-group:/aigov/*",
    ]
  }

  # The bucket that receives invocation logs and Audit Manager evidence.
  # Name-scoped to aigov-*, so this cannot touch any other bucket.
  statement {
    sid     = "GovernanceBucket"
    effect  = "Allow"
    actions = ["s3:*"]
    resources = [
      "arn:aws:s3:::aigov-*",
      "arn:aws:s3:::aigov-*/*",
    ]
  }

  # Read-only visibility of every other bucket's posture, plus the ability to
  # read objects out of the invocation-log and knowledge-base buckets.
  statement {
    sid    = "EvidenceReadOnly"
    effect = "Allow"
    actions = [
      "s3:GetAccountPublicAccessBlock",
      "s3:GetBucketAcl",
      "s3:GetBucketLocation",
      "s3:GetBucketLogging",
      "s3:GetBucketNotification",
      "s3:GetBucketObjectLockConfiguration",
      "s3:GetBucketOwnershipControls",
      "s3:GetBucketPolicy",
      "s3:GetBucketPolicyStatus",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketTagging",
      "s3:GetBucketVersioning",
      "s3:GetEncryptionConfiguration",
      "s3:GetLifecycleConfiguration",
      "s3:ListAllMyBuckets",
      "s3:ListBucket",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "InvocationLogObjectReadOnly"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
    ]
    resources = [
      "arn:aws:s3:::*bedrock-logs*/*",
      "arn:aws:s3:::*model-invocation-logs*/*",
      "arn:aws:s3:::*knowledge-base*/*",
    ]
  }

  # Delivery / remediation roles the operator creates for the controls above.
  # Path-scoped to AIGovernance-*, the same pattern AWSTransformAccess uses.
  statement {
    sid    = "GovernanceServiceRoles"
    effect = "Allow"
    actions = [
      "iam:AttachRolePolicy",
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:DetachRolePolicy",
      "iam:PutRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:UpdateRoleDescription",
    ]
    resources = ["arn:aws:iam::*:role/AIGovernance-*"]
  }

  statement {
    sid       = "GovernancePassRole"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::*:role/AIGovernance-*"]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values = [
        "bedrock.amazonaws.com",
        "config.amazonaws.com",
        "ssm.amazonaws.com",
      ]
    }
  }

  statement {
    sid       = "GovernanceServiceLinkedRoles"
    effect    = "Allow"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values = [
        "auditmanager.amazonaws.com",
        "config.amazonaws.com",
      ]
    }
  }

  # Deploy and remediate the AI posture rules (guardrail-attached,
  # sagemaker-notebook-no-direct-internet, and so on), per account and, where
  # this account is a delegated admin for Config, org-wide. ConfigRule ARNs are
  # generated, so this cannot be name-scoped.
  statement {
    sid    = "ConfigRuleEnforcement"
    effect = "Allow"
    actions = [
      "config:DeleteConfigRule",
      "config:DeleteConformancePack",
      "config:DeleteOrganizationConfigRule",
      "config:DeleteOrganizationConformancePack",
      "config:DeleteRemediationConfiguration",
      "config:DeleteRemediationExceptions",
      "config:GetOrganizationConfigRuleDetailedStatus",
      "config:GetOrganizationConformancePackDetailedStatus",
      "config:PutConfigRule",
      "config:PutConformancePack",
      "config:PutOrganizationConfigRule",
      "config:PutOrganizationConformancePack",
      "config:PutRemediationConfigurations",
      "config:PutRemediationExceptions",
      "config:PutRetentionConfiguration",
      "config:StartConfigRulesEvaluation",
      "config:StartRemediationExecution",
      "config:TagResource",
      "config:UntagResource",
    ]
    resources = ["*"]
  }

  # Read-only view of the org (accounts, OUs, policies, delegated admins) to
  # scope governance. Returns data only from the management or a delegated-admin
  # account; SCP authoring and delegated-admin registration stay in cloudlab.
  statement {
    sid    = "OrganizationsReadOnly"
    effect = "Allow"
    actions = [
      "organizations:Describe*",
      "organizations:List*",
    ]
    resources = ["*"]
  }

  # AWS Audit Manager, including its Generative AI Best Practices framework:
  # register the account, run assessments, and export evidence reports.
  statement {
    sid    = "AuditManager"
    effect = "Allow"
    actions = [
      "auditmanager:AssociateAssessmentReportEvidenceFolder",
      "auditmanager:BatchAssociateAssessmentReportEvidence",
      "auditmanager:BatchDisassociateAssessmentReportEvidence",
      "auditmanager:BatchGet*",
      "auditmanager:CreateAssessment",
      "auditmanager:CreateAssessmentFramework",
      "auditmanager:CreateAssessmentReport",
      "auditmanager:CreateControl",
      "auditmanager:DeleteAssessment",
      "auditmanager:DeleteAssessmentFramework",
      "auditmanager:DeleteAssessmentReport",
      "auditmanager:DeleteControl",
      "auditmanager:DeregisterAccount",
      "auditmanager:DisassociateAssessmentReportEvidenceFolder",
      "auditmanager:Get*",
      "auditmanager:List*",
      "auditmanager:RegisterAccount",
      "auditmanager:StartAssessmentReportEvidenceSelection",
      "auditmanager:TagResource",
      "auditmanager:UntagResource",
      "auditmanager:UpdateAssessment",
      "auditmanager:UpdateAssessmentControl",
      "auditmanager:UpdateAssessmentControlSetStatus",
      "auditmanager:UpdateAssessmentFramework",
      "auditmanager:UpdateAssessmentStatus",
      "auditmanager:UpdateControl",
      "auditmanager:UpdateSettings",
      "auditmanager:ValidateAssessmentReportIntegrity",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AuditTrailReadOnly"
    effect = "Allow"
    actions = [
      "cloudtrail:CancelQuery",
      "cloudtrail:Describe*",
      "cloudtrail:Get*",
      "cloudtrail:List*",
      "cloudtrail:LookupEvents",
      "cloudtrail:StartQuery",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ObservabilityReadOnly"
    effect = "Allow"
    actions = [
      "cloudwatch:Describe*",
      "cloudwatch:Get*",
      "cloudwatch:List*",
      "logs:Describe*",
      "logs:FilterLogEvents",
      "logs:Get*",
      "logs:List*",
      "logs:StartLiveTail",
      "logs:StartQuery",
      "logs:StopLiveTail",
      "logs:StopQuery",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ConfigReadOnly"
    effect = "Allow"
    actions = [
      "config:BatchGet*",
      "config:Describe*",
      "config:Get*",
      "config:List*",
      "config:SelectAggregateResourceConfig",
      "config:SelectResourceConfig",
    ]
    resources = ["*"]
  }

  # Security Hub and IAM Access Analyzer: the two native posture surfaces for
  # AI resources (control failures, externally shared models, over-broad
  # invoke permissions). Read plus policy-checking, no finding suppression.
  statement {
    sid    = "SecurityPostureReadOnly"
    effect = "Allow"
    actions = [
      "access-analyzer:CheckAccessNotGranted",
      "access-analyzer:CheckNoNewAccess",
      "access-analyzer:CheckNoPublicAccess",
      "access-analyzer:Get*",
      "access-analyzer:List*",
      "access-analyzer:ValidatePolicy",
      "securityhub:BatchGet*",
      "securityhub:Describe*",
      "securityhub:Get*",
      "securityhub:List*",
    ]
    resources = ["*"]
  }

  # Cost visibility for AI spend attribution (which team spends what on
  # invocation). ce:* is global and already exempt from the region lockdown.
  statement {
    sid    = "AiCostVisibility"
    effect = "Allow"
    actions = [
      "bcm-data-exports:Get*",
      "bcm-data-exports:List*",
      "ce:Describe*",
      "ce:Get*",
      "ce:List*",
      "cur:Describe*",
      "cur:Get*",
    ]
    resources = ["*"]
  }

  # Simulate* answers "who could invoke a model"; GenerateServiceLastAccessed
  # answers "who actually did". Neither changes the policies it evaluates.
  statement {
    sid    = "IamReadOnly"
    effect = "Allow"
    actions = [
      "iam:GenerateCredentialReport",
      "iam:GenerateServiceLastAccessedDetails",
      "iam:Get*",
      "iam:List*",
      "iam:SimulateCustomPolicy",
      "iam:SimulatePrincipalPolicy",
    ]
    resources = ["*"]
  }

  # Read every key's posture; use only the keys the AI services and the
  # governance bucket encrypt with, scoped by ViaService.
  statement {
    sid    = "KmsPostureReadOnly"
    effect = "Allow"
    actions = [
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListAliases",
      "kms:ListGrants",
      "kms:ListKeys",
      "kms:ListResourceTags",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "KmsViaGovernedServices"
    effect = "Allow"
    actions = [
      "kms:CreateGrant",
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:RetireGrant",
    ]
    resources = ["*"]

    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values = [
        "auditmanager.*.amazonaws.com",
        "bedrock.*.amazonaws.com",
        "logs.*.amazonaws.com",
        "s3.*.amazonaws.com",
      ]
    }
  }
}
