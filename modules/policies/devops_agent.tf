# Policy document for the one set the internal team holds today: DevOpsAgentAccess.
#
# Grouped by audience rather than one file per document, so a second internal set
# lands here instead of in a new file. The partner and governance sets are in
# aws_transform.tf and ai_governance.tf; the two documents merged into
# every set are in shared.tf.
#
# local.inline_policies in locals.tf maps each permission set to its document.
# The names do not line up: DevOpsAgentAccess is backed by devops_agent_access,
# but a set added here need not match its document's name.

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
  # The console/IAM read pair and the DevOpsAgent role plumbing, both from
  # role_plumbing.tf.
  source_policy_documents = [
    data.aws_iam_policy_document.console_and_iam_read.json,
    data.aws_iam_policy_document.role_plumbing["DevOpsAgent"].json,
  ]


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
      "sqs:ListQueueTags",
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

      "sqs:*",

      "ssm:*",
    ]
    resources = ["*"]
  }

  statement {
    sid     = "DevOpsAgentS3Scoped"
    effect  = "Allow"
    actions = ["s3:*"]
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
    sid    = "DevOpsAgentIamWriteScoped"
    effect = "Allow"
    actions = [
      "iam:AddRoleToInstanceProfile",
      "iam:AttachRolePolicy",
      "iam:CreateInstanceProfile",
      "iam:CreatePolicy",
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
}
