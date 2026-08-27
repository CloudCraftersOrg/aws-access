# Inline policies attached to permission sets, plus the region lockdown that is
# merged into all of them.
#
# To add a document: define it here, register the key below, add the key to the
# inline_policy_key validation in variables.tf, then reference it from a
# permission set.

locals {
  inline_policies = {
    power_user_access   = data.aws_iam_policy_document.power_user_access.json
    infra_modify_only   = data.aws_iam_policy_document.infra_modify_only.json
    partner_demo_access = data.aws_iam_policy_document.partner_demo_access.json
  }
}

# Denies anything outside the set's approved regions. Global and
# region-agnostic services are exempted via not_actions, otherwise console
# sign-in, IAM and billing break everywhere.
#
# Built per permission set so one set can be widened without opening the extra
# region for all of them.
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

# Despite the permission set name, this is NOT the AWS managed PowerUserAccess
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

# Read plus update/tag on workshop services, no create or destroy. Enough to
# run `terraform apply` against resources that already exist.
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

# AWS Transform demo cohort: sign in to the web app, plus deploy the legacy
# fbctf stack the demo modernizes.
#
# The AWSTransform* half is small because the service only authorizes entry to
# its web app with IAM, then hands off to its own workspace roles for everything
# done inside. Work a job performs in the account runs under a service-linked
# role, not the user's session.
#
# The Fbctf* statements exist for the cohort's own `terraform apply`, not for
# anything AWS Transform does. SIDs match what is deployed — renaming one
# rewrites the live policy, so treat them as fixed.
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
