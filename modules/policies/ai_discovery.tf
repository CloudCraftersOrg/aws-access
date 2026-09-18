# Policy document for the Condor Discovery PoC: AIDiscoveryAccess.
#
# One set for now, so it gets its own file rather than folding into an existing
# audience. local.inline_policies in locals.tf maps AIDiscoveryAccess to this
# document.
#
# Source: the condor-taskpack (58 tasks, PLAN.md + tasks/*.md) and its
# architecture diagram. Both build one AWS account in four blocks: account
# telemetry baseline, the fake client estate (var.condor_prefix), the discovery
# platform network and Lambda collectors (var.dp_prefix), and platform services
# (data lake, orchestration, analytics) outside any VPC.
#
# First pass over a large proposal - expect follow-up PRs, like EdgeAIAccess.
# Not modeled here at all: the GitHub App `dp-discovery-reader` (task P2-04)
# is not an AWS resource - it is created by hand by a GitHub org owner,
# outside this repo.
data "aws_iam_policy_document" "ai_discovery_access" {
  # The console/IAM read pair and the AIDiscovery role plumbing, both from
  # role_plumbing.tf.
  source_policy_documents = [
    data.aws_iam_policy_document.console_and_iam_read.json,
    data.aws_iam_policy_document.role_plumbing["AIDiscovery"].json,
  ]

  # Read-only discovery across everything this set touches, including the
  # managed policies its own IAM writes below cannot reach.
  statement {
    sid    = "AIDiscoveryReadOnly"
    effect = "Allow"
    actions = [
      "athena:Get*",
      "athena:List*",
      "cloudformation:Describe*",
      "cloudformation:Get*",
      "cloudformation:List*",
      "cloudtrail:Describe*",
      "cloudtrail:Get*",
      "cloudtrail:List*",
      "cloudtrail:LookupEvents",
      "compute-optimizer:Describe*",
      "compute-optimizer:Export*",
      "compute-optimizer:Get*",
      "config:Describe*",
      "config:Get*",
      "config:List*",
      "cost-optimization-hub:Get*",
      "cost-optimization-hub:List*",
      "dynamodb:Describe*",
      "dynamodb:List*",
      "ecr:Describe*",
      "ecr:Get*",
      "ecr:List*",
      "eks:Describe*",
      "eks:List*",
      "elasticache:Describe*",
      "events:Describe*",
      "events:List*",
      "glue:Get*",
      "glue:List*",
      "kms:Describe*",
      "kms:Get*",
      "kms:List*",
      "lambda:Get*",
      "lambda:List*",
      "license-manager:Get*",
      "license-manager:List*",
      "logs:Describe*",
      "logs:FilterLogEvents",
      "logs:Get*",
      "network-firewall:Describe*",
      "network-firewall:List*",
      "ram:Get*",
      "ram:List*",
      "rds:Describe*",
      "rds:List*",
      "route53resolver:Get*",
      "route53resolver:List*",
      "secretsmanager:DescribeSecret",
      "secretsmanager:ListSecrets",
      "sns:Get*",
      "sns:List*",
      "states:Describe*",
      "states:List*",
    ]
    resources = ["*"]
  }

  # Account telemetry baseline (task P1-03). None of these have a
  # resource-level ARN that is worth prefix-scoping: a recorder, an
  # aggregator, an export and the hub/optimizer enrollment are each singular
  # per account or region, not named resources a holder could create outside
  # the estate. Contained by the region lockdown and the Sandbox-only grant.
  statement {
    sid    = "AIDiscoveryTelemetryBaseline"
    effect = "Allow"
    actions = [
      "compute-optimizer:UpdateEnrollmentStatus",
      "config:BatchGet*",
      "config:DeleteConfigurationAggregator",
      "config:DeleteConfigurationRecorder",
      "config:DeleteDeliveryChannel",
      "config:Put*",
      "config:Start*",
      "config:Stop*",
      "config:TagResource",
      "config:UntagResource",
      "cost-optimization-hub:UpdateEnrollmentStatus",
      "cost-optimization-hub:UpdatePreferences",
      "ce:UpdateCostAllocationTagsStatus",
      "ce:ListCostAllocationTags",
    ]
    resources = ["*"]
  }

  # CloudTrail, the CUR2 data export and the monthly budget are all named, so
  # unlike the baseline above these are prefix-scoped.
  statement {
    sid    = "AIDiscoveryTrail"
    effect = "Allow"
    actions = [
      "cloudtrail:AddTags",
      "cloudtrail:CreateTrail",
      "cloudtrail:DeleteTrail",
      "cloudtrail:PutEventSelectors",
      "cloudtrail:RemoveTags",
      "cloudtrail:StartLogging",
      "cloudtrail:StopLogging",
      "cloudtrail:UpdateTrail",
    ]
    resources = ["arn:aws:cloudtrail:*:*:trail/${var.condor_prefix}-*"]
  }

  # bcm-data-exports is the CUR 2.0 API. Export ARNs are generated at
  # creation, so the create call itself has to be account-wide; everything
  # after it is reachable only through the export it made.
  statement {
    sid    = "AIDiscoveryDataExports"
    effect = "Allow"
    actions = [
      "bcm-data-exports:CreateExport",
      "bcm-data-exports:DeleteExport",
      "bcm-data-exports:Get*",
      "bcm-data-exports:List*",
      "bcm-data-exports:TagResource",
      "bcm-data-exports:UntagResource",
      "bcm-data-exports:UpdateExport",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AIDiscoveryBudget"
    effect = "Allow"
    actions = [
      "budgets:CreateBudget",
      "budgets:CreateBudgetAction",
      "budgets:DeleteBudget",
      "budgets:DescribeBudget",
      "budgets:ListTagsForResource",
      "budgets:ModifyBudget",
      "budgets:TagResource",
      "budgets:ViewBudget",
    ]
    resources = ["arn:aws:budgets::*:budget/${var.condor_prefix}-*"]
  }

  # The estate and platform state/log buckets. Both prefixes in one statement
  # because every bucket named by the task pack falls under one or the other:
  # condor-tfstate/config/trail/cur/flowlogs (estate) and dp-tfstate/dp-raw/
  # dp-lake/athena-results (platform).
  statement {
    sid     = "AIDiscoveryBuckets"
    effect  = "Allow"
    actions = ["s3:*"]
    resources = [
      "arn:aws:s3:::${var.condor_prefix}-*",
      "arn:aws:s3:::${var.condor_prefix}-*/*",
      "arn:aws:s3:::${var.dp_prefix}-*",
      "arn:aws:s3:::${var.dp_prefix}-*/*",
    ]
  }

  # Account-wide because the estate plants clickops/tagged-not-named
  # resources on purpose and VPC/SG ARNs are generated IDs pre-creation - not
  # reliably prefix-scoped. Same trade as DemoStackInfraDeploy in
  # aws_transform.tf: contained by the region lock and the Sandbox-only grant.
  statement {
    sid    = "AIDiscoveryEstateCompute"
    effect = "Allow"
    actions = [
      "autoscaling:*",
      "ec2:*",
      "ecs:*",
      "eks:*",
      "elasticache:*",
      "elasticloadbalancing:*",
      "network-firewall:*",
      "rds:*",
      "route53resolver:*",
      "ssm:*",
    ]
    resources = ["*"]
  }

  # dp-collector and the ~35 discovery Lambdas (tasks P2-07 through P2-15,
  # P4-01 dbt/migrate). Function names all carry the platform prefix.
  statement {
    sid       = "AIDiscoveryFunctions"
    effect    = "Allow"
    actions   = ["lambda:*"]
    resources = ["arn:aws:lambda:*:*:function:${var.dp_prefix}-*"]
  }

  # Orchestration: Step Functions, EventBridge (rule and Scheduler), SNS.
  statement {
    sid       = "AIDiscoveryStateMachines"
    effect    = "Allow"
    actions   = ["states:*"]
    resources = ["arn:aws:states:*:*:stateMachine:${var.dp_prefix}-*"]
  }

  statement {
    sid       = "AIDiscoveryEventRules"
    effect    = "Allow"
    actions   = ["events:*"]
    resources = ["arn:aws:events:*:*:rule/${var.dp_prefix}-*"]
  }

  statement {
    sid    = "AIDiscoverySchedules"
    effect = "Allow"
    actions = [
      "scheduler:CreateSchedule",
      "scheduler:DeleteSchedule",
      "scheduler:GetSchedule",
      "scheduler:TagResource",
      "scheduler:UntagResource",
      "scheduler:UpdateSchedule",
    ]
    resources = ["arn:aws:scheduler:*:*:schedule/*/${var.dp_prefix}-*"]
  }

  statement {
    sid       = "AIDiscoveryListSchedules"
    effect    = "Allow"
    actions   = ["scheduler:ListSchedules"]
    resources = ["*"]
  }

  statement {
    sid       = "AIDiscoveryTopics"
    effect    = "Allow"
    actions   = ["sns:*"]
    resources = ["arn:aws:sns:*:*:${var.dp_prefix}-*"]
  }

  # dp-run-ledger, dp-checkpoints and the two answer-key tables.
  statement {
    sid       = "AIDiscoveryTables"
    effect    = "Allow"
    actions   = ["dynamodb:*"]
    resources = ["arn:aws:dynamodb:*:*:table/${var.dp_prefix}-*"]
  }

  # The 4 customer managed keys back Object Lock, the lakehouse and Aurora.
  # Key IDs are generated at creation, so unlike the aliases that name them
  # the key itself cannot be prefix-scoped up front - the same trade
  # AWSTransformKmsViaService makes, but by service rather than ViaService
  # because this set also has to create the keys, not only use them.
  statement {
    sid    = "AIDiscoveryKeys"
    effect = "Allow"
    actions = [
      "kms:CreateAlias",
      "kms:CreateGrant",
      "kms:CreateKey",
      "kms:Decrypt",
      "kms:DeleteAlias",
      "kms:Encrypt",
      "kms:EnableKeyRotation",
      "kms:GenerateDataKey*",
      "kms:PutKeyPolicy",
      "kms:RetireGrant",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
      "kms:UpdateAlias",
    ]
    resources = ["*"]
  }

  # dp-canonical Aurora Serverless v2, named like the rest of the platform.
  statement {
    sid    = "AIDiscoveryCanonicalStore"
    effect = "Allow"
    actions = [
      "rds-data:*",
      "rds:AddTagsToResource",
      "rds:CreateDBCluster",
      "rds:CreateDBInstance",
      "rds:DeleteDBCluster",
      "rds:DeleteDBInstance",
      "rds:ModifyDBCluster",
      "rds:ModifyDBInstance",
      "rds:RemoveTagsFromResource",
    ]
    resources = [
      "arn:aws:rds:*:*:cluster:${var.dp_prefix}-*",
      "arn:aws:rds:*:*:db:${var.dp_prefix}-*",
      "arn:aws:rds:*:*:subgrp:${var.dp_prefix}-*",
    ]
  }

  # dp_lake database, dp-analytics Athena workgroup. The catalog resource is
  # required alongside the named one for most Glue calls, as in
  # EdgeAIAnalytics.
  statement {
    sid     = "AIDiscoveryLakehouse"
    effect  = "Allow"
    actions = ["glue:*"]
    resources = [
      "arn:aws:glue:*:*:catalog",
      "arn:aws:glue:*:*:crawler/${var.dp_prefix}-*",
      "arn:aws:glue:*:*:database/${replace(var.dp_prefix, "-", "_")}_*",
      "arn:aws:glue:*:*:table/${replace(var.dp_prefix, "-", "_")}_*/*",
    ]
  }

  statement {
    sid       = "AIDiscoveryAthena"
    effect    = "Allow"
    actions   = ["athena:*"]
    resources = ["arn:aws:athena:*:*:workgroup/${var.dp_prefix}-*"]
  }

  # The dbt Lambda container image (ADR-039).
  statement {
    sid       = "AIDiscoveryEcrAuth"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid       = "AIDiscoveryEcr"
    effect    = "Allow"
    actions   = ["ecr:*"]
    resources = ["arn:aws:ecr:*:*:repository/${var.dp_prefix}-*"]
  }

  # dp/* only, matching the dp-collector role's own scope in task P2-04:
  # GetSecretValue on dp/* and an explicit deny on condor/* there. This set
  # additionally needs the write verbs dp-collector does not, to create the
  # secrets in the first place.
  statement {
    sid    = "AIDiscoverySecrets"
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
    resources = ["arn:aws:secretsmanager:*:*:secret:${var.dp_prefix}/*"]
  }

  # Roles/policies this set's own stacks manage (condor-bootstrap,
  # dp-deployer, the two boundaries, dp-collector, the Lambda execution
  # roles). CreateRole itself lives in role_plumbing.tf's AIDiscovery scope,
  # not here - iam:PermissionsBoundary only exists as a condition on that call.
  #
  # DenyAdminPolicyAttachment (shared.tf) still blocks attaching
  # AdministratorAccess/IAMFullAccess/PowerUserAccess to anything created
  # here, so this cannot reproduce the task pack's literal dp-deployer design.
  # See the PR description for that trade.
  statement {
    sid    = "AIDiscoveryIamWriteScoped"
    effect = "Allow"
    actions = [
      "iam:AttachRolePolicy",
      "iam:CreateInstanceProfile",
      "iam:CreatePolicy",
      "iam:CreatePolicyVersion",
      "iam:DeleteInstanceProfile",
      "iam:DeletePolicy",
      "iam:DeletePolicyVersion",
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:DetachRolePolicy",
      "iam:PutRolePolicy",
      "iam:SetDefaultPolicyVersion",
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
      "arn:aws:iam::*:instance-profile/${var.condor_prefix}-*",
      "arn:aws:iam::*:instance-profile/${var.dp_prefix}-*",
      "arn:aws:iam::*:policy/${var.condor_prefix}-*",
      "arn:aws:iam::*:policy/${var.dp_prefix}-*",
      "arn:aws:iam::*:role/${var.condor_prefix}-*",
      "arn:aws:iam::*:role/${var.dp_prefix}-*",
    ]
  }

  # Creating condor-bootstrap/dp-deployer (above) is pointless without this:
  # a role's trust policy alone doesn't let the caller assume it, the
  # caller's own identity policy has to allow sts:AssumeRole too.
  statement {
    sid     = "AIDiscoveryAssumeOwnRoles"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    resources = [
      "arn:aws:iam::*:role/${var.condor_prefix}-*",
      "arn:aws:iam::*:role/${var.dp_prefix}-*",
    ]
  }

  # EKS access entries for dp-collector (task P2-04) and the human-owned
  # planted IAM users (dev.*, svc.*) the estate needs. iam:CreateUser itself
  # is out of scope for every set in this repo except the base repo's own
  # bootstrap - this set only manages the users' presence in the estate's
  # answer key metadata, not real credentials.
  statement {
    sid    = "AIDiscoveryEksAccess"
    effect = "Allow"
    actions = [
      "eks:AssociateAccessPolicy",
      "eks:CreateAccessEntry",
      "eks:DeleteAccessEntry",
      "eks:DisassociateAccessPolicy",
      "eks:TagResource",
    ]
    resources = ["arn:aws:eks:*:*:access-entry/${var.condor_prefix}-*/*"]
  }

  # CID's dashboard/dataset/data-source IDs (task P2-06) come from AWS's own
  # template, not ours to prefix - quicksight:* like bedrock:*/transform:*
  # in aws_transform.tf, contained by the region lock and Sandbox-only grant.
  statement {
    sid       = "AIDiscoveryDashboards"
    effect    = "Allow"
    actions   = ["quicksight:*"]
    resources = ["*"]
  }

  # The CID dashboards install from a CloudFormation stack (task P2-06),
  # named with the platform prefix like everything else this set creates -
  # unlike the QuickSight resources it installs, covered above.
  statement {
    sid    = "AIDiscoveryCidStack"
    effect = "Allow"
    actions = [
      "cloudformation:CreateStack",
      "cloudformation:DeleteStack",
      "cloudformation:TagResource",
      "cloudformation:UntagResource",
      "cloudformation:UpdateStack",
    ]
    resources = ["arn:aws:cloudformation:*:*:stack/${var.dp_prefix}-*/*"]
  }

  statement {
    sid    = "AIDiscoveryCloudFormationAccountWide"
    effect = "Allow"
    actions = [
      "cloudformation:CreateUploadBucket",
      "cloudformation:ValidateTemplate",
    ]
    resources = ["*"]
  }

  # Well-Architected workload reviews backing the business case (tasks
  # P5-01 through P5-04). Workload IDs are service-generated at creation, so
  # unlike everything else this set creates they can't be prefix-scoped up
  # front - the same trade as AIDiscoveryKeys above.
  statement {
    sid       = "AIDiscoveryWellArchitected"
    effect    = "Allow"
    actions   = ["wellarchitected:*"]
    resources = ["*"]
  }
}
