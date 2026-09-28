# Policy document for the AI-augmented support cohort: AIAugmentedSupportAccess.
#
# One set for now, so it gets its own file rather than folding into an existing
# audience. local.inline_policies in locals.tf maps AIAugmentedSupportAccess to
# this document.
#
# Three blocks: Amazon Connect with Amazon Q in Connect for the contact centre,
# Bedrock (models, agents, knowledge bases, guardrails) for the assistant behind
# it, and a serverless app stack (Lambda, API Gateway, DynamoDB, S3) that glues
# the two together. Everything nameable is scoped to var.ai_support_prefix.
#
# First pass: the cohort's repo has no resources yet, so this is written against
# the intended architecture, not a working stack. Expect follow-up PRs as live
# AccessDenied errors come in, like every other set here.
#
# Not covered: a vector store for knowledge bases. OpenSearch Serverless was left
# out on purpose. A knowledge base backed by S3 Vectors or an ai-support-* bucket
# works with what is here; anything else needs its own statement.
data "aws_iam_policy_document" "ai_augmented_support_access" {
  # The console/IAM read pair and the AIAugmentedSupport role plumbing, both from
  # role_plumbing.tf.
  source_policy_documents = [
    data.aws_iam_policy_document.console_and_iam_read.json,
    data.aws_iam_policy_document.role_plumbing["AIAugmentedSupport"].json,
  ]

  # Read-only discovery across everything this set touches.
  statement {
    sid    = "AIAugmentedSupportReadOnly"
    effect = "Allow"
    actions = [
      "apigateway:GET",
      "cloudwatch:Describe*",
      "cloudwatch:Get*",
      "cloudwatch:List*",
      "dynamodb:Describe*",
      "dynamodb:List*",
      "lambda:Get*",
      "lambda:List*",
      "logs:Describe*",
      "logs:FilterLogEvents",
      "logs:Get*",
      "logs:List*",
      "logs:StartQuery",
      "logs:StopQuery",
      "s3:GetBucketLocation",
      "s3:ListAllMyBuckets",
      "secretsmanager:DescribeSecret",
      "secretsmanager:ListSecrets",
    ]
    resources = ["*"]
  }

  # Amazon Connect: instance, flows, queues, routing, users and integrations.
  #
  # connect:* on "*" because every Connect ARN is keyed by a generated instance
  # ID, not a name, so there is no prefix to scope to. Contained by the region
  # lockdown and the Sandbox-only grant.
  statement {
    sid       = "AIAugmentedSupportConnect"
    effect    = "Allow"
    actions   = ["connect:*"]
    resources = ["*"]
  }

  # Amazon Q in Connect authorizes under the `wisdom` service prefix, and it
  # reaches its content sources through AppIntegrations. Both use generated IDs.
  statement {
    sid    = "AIAugmentedSupportQInConnect"
    effect = "Allow"
    actions = [
      "app-integrations:*",
      "wisdom:*",
    ]
    resources = ["*"]
  }

  # CreateInstance provisions a Directory Service alias behind the scenes, even
  # with Connect-managed identity, and fails without these.
  statement {
    sid    = "AIAugmentedSupportConnectDirectory"
    effect = "Allow"
    actions = [
      "ds:AuthorizeApplication",
      "ds:CheckAlias",
      "ds:CreateAlias",
      "ds:CreateIdentityPoolDirectory",
      "ds:DeleteDirectory",
      "ds:DescribeDirectories",
      "ds:UnauthorizeApplication",
    ]
    resources = ["*"]
  }

  # Bedrock models, agents, knowledge bases, flows and guardrails.
  #
  # bedrock:* on "*" as in TransformAgentsBedrock: agent, knowledge base and
  # guardrail ARNs are generated IDs, and foundation models are AWS-owned. What
  # contains it is the region lockdown and the Sandbox-only grant.
  statement {
    sid       = "AIAugmentedSupportBedrock"
    effect    = "Allow"
    actions   = ["bedrock:*"]
    resources = ["*"]
  }

  statement {
    sid       = "AIAugmentedSupportLambda"
    effect    = "Allow"
    actions   = ["lambda:*"]
    resources = ["arn:aws:lambda:*:*:function:${var.ai_support_prefix}-*"]
  }

  # Event source mapping and layer ARNs are not name-based, or not owned by the
  # cohort (public layers).
  statement {
    sid    = "AIAugmentedSupportLambdaAccountLevel"
    effect = "Allow"
    actions = [
      "lambda:CreateEventSourceMapping",
      "lambda:DeleteEventSourceMapping",
      "lambda:GetLayerVersion",
      "lambda:UpdateEventSourceMapping",
    ]
    resources = ["*"]
  }

  # API IDs are generated, so the only possible scope is the service's whole
  # path space. apigateway:GET is already in the read statement.
  statement {
    sid    = "AIAugmentedSupportApiGateway"
    effect = "Allow"
    actions = [
      "apigateway:DELETE",
      "apigateway:PATCH",
      "apigateway:POST",
      "apigateway:PUT",
      "apigateway:TagResource",
      "apigateway:UntagResource",
    ]
    resources = ["arn:aws:apigateway:*::/*"]
  }

  statement {
    sid       = "AIAugmentedSupportTables"
    effect    = "Allow"
    actions   = ["dynamodb:*"]
    resources = ["arn:aws:dynamodb:*:*:table/${var.ai_support_prefix}-*"]
  }

  # Knowledge base source documents, Connect recordings and transcripts, and
  # Lambda artifacts.
  statement {
    sid     = "AIAugmentedSupportBuckets"
    effect  = "Allow"
    actions = ["s3:*"]
    resources = [
      "arn:aws:s3:::${var.ai_support_prefix}-*",
      "arn:aws:s3:::${var.ai_support_prefix}-*/*",
    ]
  }

  statement {
    sid    = "AIAugmentedSupportSecrets"
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
    resources = ["arn:aws:secretsmanager:*:*:secret:${var.ai_support_prefix}-*"]
  }

  # Lambda writes to /aws/lambda/<function>, Connect to /aws/connect/<alias>.
  statement {
    sid    = "AIAugmentedSupportLogGroups"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:DeleteLogGroup",
      "logs:PutLogEvents",
      "logs:PutRetentionPolicy",
      "logs:TagLogGroup",
      "logs:TagResource",
    ]
    resources = [
      "arn:aws:logs:*:*:log-group:/${var.ai_support_prefix}/*",
      "arn:aws:logs:*:*:log-group:/aws/connect/${var.ai_support_prefix}-*",
      "arn:aws:logs:*:*:log-group:/aws/lambda/${var.ai_support_prefix}-*",
    ]
  }

  statement {
    sid    = "AIAugmentedSupportAlarms"
    effect = "Allow"
    actions = [
      "cloudwatch:DeleteAlarms",
      "cloudwatch:DeleteDashboards",
      "cloudwatch:PutDashboard",
      "cloudwatch:PutMetricAlarm",
      "cloudwatch:TagResource",
      "cloudwatch:UntagResource",
    ]
    resources = [
      "arn:aws:cloudwatch::*:dashboard/${var.ai_support_prefix}-*",
      "arn:aws:cloudwatch:*:*:alarm:${var.ai_support_prefix}-*",
    ]
  }

  # Roles for the cohort's Lambda functions, Bedrock agents and knowledge bases.
  # CreateRole itself is generated by role_plumbing.tf's AIAugmentedSupport
  # scope, not here: the iam:PermissionsBoundary condition key only exists on
  # that call and has to stay on its own statement.
  statement {
    sid    = "AIAugmentedSupportIamWriteScoped"
    effect = "Allow"
    actions = [
      "iam:AttachRolePolicy",
      "iam:CreatePolicy",
      "iam:CreatePolicyVersion",
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
      "arn:aws:iam::*:policy/${var.ai_support_prefix}-*",
      "arn:aws:iam::*:role/${var.ai_support_prefix}-*",
    ]
  }
}
