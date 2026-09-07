# Policy document for the Edge AI Landing Zone pilot: EdgeAIAccess.
#
# One set for now, so it gets its own file rather than folding into an existing
# audience. local.inline_policies in locals.tf maps EdgeAIAccess to this
# document.

# Used by: EdgeAIAccess.
#
# Edge AI Landing Zone pilot: model delivery, fleet control and inference
# observability for edge/IoT devices. Everything it creates is scoped to
# var.edge_ai_prefix. First pass over a large proposal - expect follow-up PRs,
# like every other set in this file.
data "aws_iam_policy_document" "edge_ai_access" {
  # The console/IAM read pair and the EdgeAI role plumbing, both from
  # role_plumbing.tf.
  source_policy_documents = [
    data.aws_iam_policy_document.console_and_iam_read.json,
    data.aws_iam_policy_document.role_plumbing["EdgeAI"].json,
  ]

  # Read-only discovery across everything this set touches.
  statement {
    sid    = "EdgeAIReadOnly"
    effect = "Allow"
    actions = [
      "batch:Describe*",
      "batch:List*",
      "cloudwatch:Describe*",
      "cloudwatch:Get*",
      "cloudwatch:List*",
      "dynamodb:Describe*",
      "dynamodb:List*",
      "ecr:Describe*",
      "ecr:Get*",
      "ecr:List*",
      "eks:Describe*",
      "eks:List*",
      "firehose:Describe*",
      "firehose:List*",
      "glue:Get*",
      "glue:List*",
      "grafana:Describe*",
      "grafana:List*",
      "greengrass:Get*",
      "greengrass:List*",
      "iot:Describe*",
      "iot:Get*",
      "iot:List*",
      "iot:SearchIndex",
      "iotsitewise:Describe*",
      "iotsitewise:List*",
      "kinesisvideo:Describe*",
      "kinesisvideo:List*",
      "logs:Describe*",
      "logs:FilterLogEvents",
      "logs:Get*",
      "logs:List*",
      "neptune-db:GetEngineStatus",
      "rds:Describe*",
      "rds:List*",
      "sagemaker:Describe*",
      "sagemaker:List*",
      "secretsmanager:DescribeSecret",
      "secretsmanager:ListSecrets",
      "timestream:Describe*",
      "timestream:List*",
    ]
    resources = ["*"]
  }

  # Not iot:*: most iot: actions don't support resource-level ARNs, only
  # Thing/ThingGroup/Job/Rule do. Rule names can't contain hyphens.
  statement {
    sid    = "EdgeAIThingsJobsAndRules"
    effect = "Allow"
    actions = [
      "iot:AddThingToThingGroup",
      "iot:AttachPolicy",
      "iot:AttachThingPrincipal",
      "iot:CancelJob",
      "iot:CreateJob",
      "iot:CreatePolicy",
      "iot:CreateThing",
      "iot:CreateThingGroup",
      "iot:CreateTopicRule",
      "iot:DeleteJob",
      "iot:DeletePolicy",
      "iot:DeleteThing",
      "iot:DeleteThingGroup",
      "iot:DeleteThingShadow",
      "iot:DeleteTopicRule",
      "iot:DetachPolicy",
      "iot:DetachThingPrincipal",
      "iot:GetThingShadow",
      "iot:RemoveThingFromThingGroup",
      "iot:ReplaceTopicRule",
      "iot:TagResource",
      "iot:UntagResource",
      "iot:UpdateJob",
      "iot:UpdateThing",
      "iot:UpdateThingGroup",
      "iot:UpdateThingShadow",
    ]
    resources = [
      "arn:aws:iot:*:*:job/${var.edge_ai_prefix}-*",
      "arn:aws:iot:*:*:policy/${var.edge_ai_prefix}-*",
      "arn:aws:iot:*:*:rule/${replace(var.edge_ai_prefix, "-", "_")}_*",
      "arn:aws:iot:*:*:thing/${var.edge_ai_prefix}-*",
      "arn:aws:iot:*:*:thinggroup/${var.edge_ai_prefix}-*",
    ]
  }

  # Asset/model/stream IDs are generated, not name-based - can't prefix-scope.
  statement {
    sid    = "EdgeAISiteWiseAndVideo"
    effect = "Allow"
    actions = [
      "iotsitewise:BatchPutAssetPropertyValue",
      "iotsitewise:CreateAsset",
      "iotsitewise:CreateAssetModel",
      "iotsitewise:DeleteAsset",
      "iotsitewise:DeleteAssetModel",
      "iotsitewise:GetAssetPropertyValue",
      "iotsitewise:TagResource",
      "iotsitewise:UpdateAsset",
      "iotsitewise:UpdateAssetModel",
      "kinesisvideo:CreateStream",
      "kinesisvideo:DeleteStream",
      "kinesisvideo:GetDataEndpoint",
      "kinesisvideo:TagStream",
      "kinesisvideo:UpdateStream",
    ]
    resources = ["*"]
  }

  # Account-level, not per-thing - can't be scoped further.
  statement {
    sid    = "EdgeAIDeviceDefender"
    effect = "Allow"
    actions = [
      "iot:AttachSecurityProfile",
      "iot:CreateSecurityProfile",
      "iot:ListAuditFindings",
      "iot:StartAuditTask",
      "iot:UpdateAccountAuditConfiguration",
      "iot:UpdateSecurityProfile",
    ]
    resources = ["*"]
  }

  # Greengrass component and core-device ARNs are name-based.
  statement {
    sid    = "EdgeAIFleetDeploy"
    effect = "Allow"
    actions = [
      "greengrass:CreateComponentVersion",
      "greengrass:DeleteComponent",
      "greengrass:TagResource",
    ]
    resources = ["arn:aws:greengrass:*:*:components:${var.edge_ai_prefix}-*"]
  }

  statement {
    sid    = "EdgeAIFleetCoreDevices"
    effect = "Allow"
    actions = [
      "greengrass:BatchAssociateClientDeviceWithCoreDevice",
      "greengrass:BatchDisassociateClientDeviceWithCoreDevice",
      "greengrass:DeleteCoreDevice",
    ]
    resources = ["arn:aws:greengrass:*:*:coreDevices:${var.edge_ai_prefix}-*"]
  }

  # Deployment IDs are generated at creation - can't be scoped up front.
  statement {
    sid    = "EdgeAIFleetDeployments"
    effect = "Allow"
    actions = [
      "greengrass:CancelDeployment",
      "greengrass:CreateDeployment",
    ]
    resources = ["*"]
  }

  # Patch baseline/window IDs are generated - stays account-wide.
  statement {
    sid    = "EdgeAIPatching"
    effect = "Allow"
    actions = [
      "ssm:CreateMaintenanceWindow",
      "ssm:CreatePatchBaseline",
      "ssm:DeletePatchBaseline",
      "ssm:DeregisterPatchBaselineForPatchGroup",
      "ssm:RegisterPatchBaselineForPatchGroup",
      "ssm:RegisterTargetWithMaintenanceWindow",
      "ssm:RegisterTaskWithMaintenanceWindow",
      "ssm:SendCommand",
      "ssm:UpdateMaintenanceWindow",
      "ssm:UpdatePatchBaseline",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "EdgeAISecrets"
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
    resources = ["arn:aws:secretsmanager:*:*:secret:${var.edge_ai_prefix}-*"]
  }

  statement {
    sid     = "EdgeAIBuckets"
    effect  = "Allow"
    actions = ["s3:*"]
    resources = [
      "arn:aws:s3:::${var.edge_ai_prefix}-*",
      "arn:aws:s3:::${var.edge_ai_prefix}-*/*",
    ]
  }

  statement {
    sid       = "EdgeAITables"
    effect    = "Allow"
    actions   = ["dynamodb:*"]
    resources = ["arn:aws:dynamodb:*:*:table/${var.edge_ai_prefix}-*"]
  }

  # Aurora and Neptune share the RDS control plane; ARNs are name-based.
  statement {
    sid    = "EdgeAIRelationalAndGraph"
    effect = "Allow"
    actions = [
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
      "arn:aws:rds:*:*:cluster:${var.edge_ai_prefix}-*",
      "arn:aws:rds:*:*:db:${var.edge_ai_prefix}-*",
      "arn:aws:rds:*:*:subgrp:${var.edge_ai_prefix}-*",
    ]
  }

  # Neptune's Data API addresses a generated resource ID, not a name - can't
  # prefix-scope until the cluster exists.
  statement {
    sid    = "EdgeAIGraphQuery"
    effect = "Allow"
    actions = [
      "neptune-db:DeleteDataViaQuery",
      "neptune-db:ReadDataViaQuery",
      "neptune-db:WriteDataViaQuery",
      "neptune-db:connect",
    ]
    resources = ["*"]
  }

  # The catalog resource is required alongside the named one for most Glue calls.
  statement {
    sid    = "EdgeAIAnalytics"
    effect = "Allow"
    actions = [
      "glue:BatchDeleteTable",
      "glue:CreateCrawler",
      "glue:CreateDatabase",
      "glue:CreateJob",
      "glue:CreateTable",
      "glue:DeleteCrawler",
      "glue:DeleteDatabase",
      "glue:DeleteJob",
      "glue:DeleteTable",
      "glue:StartCrawler",
      "glue:StartJobRun",
      "glue:TagResource",
      "glue:UpdateCrawler",
      "glue:UpdateDatabase",
      "glue:UpdateJob",
      "glue:UpdateTable",
    ]
    resources = [
      "arn:aws:glue:*:*:catalog",
      "arn:aws:glue:*:*:crawler/${var.edge_ai_prefix}-*",
      "arn:aws:glue:*:*:database/${var.edge_ai_prefix}-*",
      "arn:aws:glue:*:*:job/${var.edge_ai_prefix}-*",
      "arn:aws:glue:*:*:table/${var.edge_ai_prefix}-*/*",
    ]
  }

  statement {
    sid    = "EdgeAITrain"
    effect = "Allow"
    actions = [
      "sagemaker:AddTags",
      "sagemaker:CreateEndpoint",
      "sagemaker:CreateEndpointConfig",
      "sagemaker:CreateModel",
      "sagemaker:CreateTrainingJob",
      "sagemaker:DeleteEndpoint",
      "sagemaker:DeleteEndpointConfig",
      "sagemaker:DeleteModel",
      "sagemaker:DeleteTags",
      "sagemaker:InvokeEndpoint",
      "sagemaker:StopTrainingJob",
      "sagemaker:UpdateEndpoint",
    ]
    resources = [
      "arn:aws:sagemaker:*:*:endpoint-config/${var.edge_ai_prefix}-*",
      "arn:aws:sagemaker:*:*:endpoint/${var.edge_ai_prefix}-*",
      "arn:aws:sagemaker:*:*:model/${var.edge_ai_prefix}-*",
      "arn:aws:sagemaker:*:*:training-job/${var.edge_ai_prefix}-*",
    ]
  }

  statement {
    sid    = "EdgeAIBatch"
    effect = "Allow"
    actions = [
      "batch:CreateComputeEnvironment",
      "batch:CreateJobQueue",
      "batch:DeleteComputeEnvironment",
      "batch:DeleteJobQueue",
      "batch:DeregisterJobDefinition",
      "batch:RegisterJobDefinition",
      "batch:SubmitJob",
      "batch:TagResource",
      "batch:TerminateJob",
      "batch:UpdateComputeEnvironment",
      "batch:UpdateJobQueue",
    ]
    resources = [
      "arn:aws:batch:*:*:compute-environment/${var.edge_ai_prefix}-*",
      "arn:aws:batch:*:*:job-definition/${var.edge_ai_prefix}-*",
      "arn:aws:batch:*:*:job-queue/${var.edge_ai_prefix}-*",
    ]
  }

  statement {
    sid       = "EdgeAIEks"
    effect    = "Allow"
    actions   = ["eks:*"]
    resources = ["arn:aws:eks:*:*:cluster/${var.edge_ai_prefix}-*"]
  }

  statement {
    sid       = "EdgeAIEcrAuth"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid       = "EdgeAIEcr"
    effect    = "Allow"
    actions   = ["ecr:*"]
    resources = ["arn:aws:ecr:*:*:repository/${var.edge_ai_prefix}-*"]
  }

  statement {
    sid       = "EdgeAIController"
    effect    = "Allow"
    actions   = ["lambda:*"]
    resources = ["arn:aws:lambda:*:*:function:${var.edge_ai_prefix}-*"]
  }

  statement {
    sid    = "EdgeAIEventStream"
    effect = "Allow"
    actions = [
      "firehose:CreateDeliveryStream",
      "firehose:DeleteDeliveryStream",
      "firehose:TagDeliveryStream",
      "firehose:UpdateDestination",
    ]
    resources = ["arn:aws:firehose:*:*:deliverystream/${var.edge_ai_prefix}-*"]
  }

  statement {
    sid    = "EdgeAITimeSeries"
    effect = "Allow"
    actions = [
      "timestream:CreateDatabase",
      "timestream:CreateTable",
      "timestream:DeleteDatabase",
      "timestream:DeleteTable",
      "timestream:DescribeEndpoints",
      "timestream:Select",
      "timestream:UpdateTable",
      "timestream:WriteRecords",
    ]
    resources = [
      "arn:aws:timestream:*:*:database/${var.edge_ai_prefix}-*",
      "arn:aws:timestream:*:*:database/${var.edge_ai_prefix}-*/table/*",
    ]
  }

  statement {
    sid    = "EdgeAIGates"
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
      "arn:aws:cloudwatch::*:dashboard/${var.edge_ai_prefix}-*",
      "arn:aws:cloudwatch:*:*:alarm:${var.edge_ai_prefix}-*",
    ]
  }

  # Workspace IDs are generated - stays account-wide.
  statement {
    sid    = "EdgeAIDashboards"
    effect = "Allow"
    actions = [
      "grafana:CreateWorkspace",
      "grafana:CreateWorkspaceApiKey",
      "grafana:DeleteWorkspace",
      "grafana:TagResource",
      "grafana:UpdateWorkspace",
      "grafana:UpdateWorkspaceConfiguration",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "EdgeAILogGroups"
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
    resources = ["arn:aws:logs:*:*:log-group:/${var.edge_ai_prefix}/*"]
  }

  # Roles this pilot's own services assume, scoped by prefix. CreateRole itself
  # is generated by role_plumbing.tf's EdgeAI scope, not here: the
  # iam:PermissionsBoundary condition key only exists on that call and has to
  # stay on its own statement.
  statement {
    sid    = "EdgeAIIamWriteScoped"
    effect = "Allow"
    actions = [
      "iam:AttachRolePolicy",
      "iam:CreateInstanceProfile",
      "iam:CreatePolicy",
      "iam:DeleteInstanceProfile",
      "iam:DeletePolicy",
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:DetachRolePolicy",
      "iam:PutRolePolicy",
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
      "arn:aws:iam::*:instance-profile/${var.edge_ai_prefix}-*",
      "arn:aws:iam::*:policy/${var.edge_ai_prefix}-*",
      "arn:aws:iam::*:role/${var.edge_ai_prefix}-*",
    ]
  }
}
