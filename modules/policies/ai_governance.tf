# Policy documents for the AI governance offering, in order: AIGovernanceAccess,
# the least-privilege set granted on Sandbox, then AIGovernanceAdminAccess, the
# near-admin set granted only on the management account.
#
# Together in one file because they are two halves of one offering and are read
# together. The second exists to do the organization-level work the first cannot:
# creating and attaching SCPs, registering delegated administrators and enabling
# service access only work from the management account.
#
# local.inline_policies in locals.tf maps each permission set to its document.


# Used by: AIGovernanceAccess.
#
# The AI governance operator: inventory every AI service, invoke and evaluate
# Bedrock models to validate the controls, enforce those controls at account and
# organization level (guardrails, invocation logging, Config rules, SCPs, Audit
# Manager), and produce the audit evidence. Read is account-wide; provisioning
# write is confined to the controls and to AIGovernance-* / aigov-* resources.
#
# organizations:* write only functions from the management or a delegated-admin
# account - see the AIGovernanceAdminAccess grant. bedrock:InvokeModel is granted (the wider
# AI services' inference verbs are not): the operator runs Bedrock to red-team
# its own guardrails, accepting that those calls land in the trail it audits.
data "aws_iam_policy_document" "ai_governance_access" {
  # CreateRole behind the boundary, PassRole and the service-linked roles, all
  # from role_plumbing.tf. IamReadOnly below is this document's own: it is
  # wider than the shared read pair.
  source_policy_documents = [
    data.aws_iam_policy_document.role_plumbing["Governance"].json,
  ]

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


  statement {
    sid    = "GovernanceServiceRoles"
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
      "iam:UpdateRoleDescription",
    ]
    resources = ["arn:aws:iam::*:role/AIGovernance-*"]
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
# Used by: AIGovernanceAdminAccess, granted only on the management account.
#
# WHAT THIS IS FOR
#
# Enforcing AI governance across the organization means operating the org control
# plane: writing and attaching SCPs, registering delegated administrators for
# Config, Audit Manager and Bedrock, and enabling org-wide service access. None of
# those calls work from a member account, which is why this exists as a separate
# set granted only on management.
#
# WHAT IT IS NOT
#
# It is not near-admin on everything. It is an allowlist: Organizations write, the
# org-level controls, and read. Adding a service here is a deliberate line, and
# `Allow "*" on "*"` pared back with denies is explicitly not the shape - that
# grants EC2, RDS, S3, Lambda and everything else across eight regions.
#
# It also does NOT repeat what AIGovernanceAccess grants. A holder who needs the
# AI-service inventory, guardrail management and evidence collection holds that
# set too - they are in the same group. Composing the two documents would double
# the bytes and put this one near the 10,240-byte cap for no gain.
#
# ACCOUNT LIFECYCLE IS NOT HERE
#
# Creating, closing, inviting, moving or removing accounts belongs to the base
# repository, which owns the organization's shape. The denies at the bottom make
# that boundary enforceable rather than conventional, because SCPs do not apply to
# the management account and nothing else would stop it.
data "aws_iam_policy_document" "ai_governance_admin_access" {
  # Read across the whole org control plane. Broad on purpose: seeing the current
  # posture is the prerequisite for changing it, and none of these grants mutate.
  statement {
    sid    = "OrganizationsReadOnly"
    effect = "Allow"
    actions = [
      "account:Get*",
      "account:List*",
      "organizations:Describe*",
      "organizations:List*",
    ]
    resources = ["*"]
  }

  # The core of the offering: SCPs and RCPs that constrain AI service usage
  # org-wide, plus the policy types that have to be enabled before they attach.
  #
  # Delete and Detach are included. They are recoverable - the base repository
  # reattaches the SCPs it owns on its next apply - and an operator who can only
  # add controls cannot iterate on them.
  statement {
    sid    = "OrganizationsPolicyManagement"
    effect = "Allow"
    actions = [
      "organizations:AttachPolicy",
      "organizations:CreatePolicy",
      "organizations:DeletePolicy",
      "organizations:DetachPolicy",
      "organizations:DisablePolicyType",
      "organizations:EnablePolicyType",
      "organizations:TagResource",
      "organizations:UntagResource",
      "organizations:UpdatePolicy",
    ]
    resources = ["*"]
  }

  # Delegating Config, Audit Manager and Bedrock administration to a member
  # account, and switching on the org-wide integrations those depend on. Both are
  # management-account-only calls.
  statement {
    sid    = "OrganizationsDelegatedAdministration"
    effect = "Allow"
    actions = [
      "organizations:DeregisterDelegatedAdministrator",
      "organizations:DisableAWSServiceAccess",
      "organizations:EnableAWSServiceAccess",
      "organizations:RegisterDelegatedAdministrator",
    ]
    resources = ["*"]
  }

  # Organizational units, because which OU an account sits in decides which SCPs
  # reach it. Creating and renaming an OU is in scope; deleting one is not, since
  # that is the organization's shape.
  statement {
    sid    = "OrganizationsUnitManagement"
    effect = "Allow"
    actions = [
      "organizations:CreateOrganizationalUnit",
      "organizations:MoveAccount",
      "organizations:UpdateOrganizationalUnit",
    ]
    resources = ["*"]
  }

  # The org-level halves of the governance controls. Their per-account halves are
  # in ai_governance_access; these only function from here or from a delegated
  # administrator, which is what the statements above set up.
  statement {
    sid    = "OrganizationControlPlane"
    effect = "Allow"
    actions = [
      "auditmanager:*",
      "config:DeleteOrganizationConfigRule",
      "config:DeleteOrganizationConformancePack",
      "config:Describe*",
      "config:Get*",
      "config:List*",
      "config:PutConfigurationAggregator",
      "config:PutOrganizationConfigRule",
      "config:PutOrganizationConformancePack",
      "controltower:Get*",
      "controltower:List*",
    ]
    resources = ["*"]
  }

  # Reading the audit surface: the org trail's configuration and the events in it.
  # Write is denied below, so this cannot be used to cover tracks.
  statement {
    sid    = "AuditTrailReadOnly"
    effect = "Allow"
    actions = [
      "cloudtrail:Describe*",
      "cloudtrail:Get*",
      "cloudtrail:List*",
      "cloudtrail:LookupEvents",
    ]
    resources = ["*"]
  }

  # Who holds what, so the operator can audit access without being able to change
  # it. The matching denies are below.
  statement {
    sid    = "AccessPostureReadOnly"
    effect = "Allow"
    actions = [
      "iam:GenerateCredentialReport",
      "iam:Get*",
      "iam:List*",
      "iam:Simulate*",
      "identitystore:Describe*",
      "identitystore:Get*",
      "identitystore:List*",
      "sso:Describe*",
      "sso:Get*",
      "sso:List*",
    ]
    resources = ["*"]
  }

  # PreventLeavingOrganization, the SCP that would otherwise cover the first two,
  # does not apply to the management account. Nothing else does either, so these
  # are the only thing standing between this set and an unrecoverable mistake.
  statement {
    sid    = "DenyIrreversibleOrganizationChanges"
    effect = "Deny"
    actions = [
      "organizations:CloseAccount",
      "organizations:CreateAccount",
      "organizations:CreateGovCloudAccount",
      "organizations:DeleteOrganization",
      "organizations:DeleteOrganizationalUnit",
      "organizations:InviteAccountToOrganization",
      "organizations:LeaveOrganization",
      "organizations:RemoveAccountFromOrganization",
    ]
    resources = ["*"]
  }

  # Belt and suspenders on the two surfaces the allowlist above deliberately
  # leaves out. Identity Center write is how a holder would grant themselves
  # AdministratorAccess everywhere; CloudTrail write is how they would hide it.
  # Neither is granted, so these cost nothing and survive a future widening.
  statement {
    sid    = "DenyAccessSystemAndAuditWrites"
    effect = "Deny"
    actions = [
      "cloudtrail:Delete*",
      "cloudtrail:Put*",
      "cloudtrail:Stop*",
      "cloudtrail:Update*",
      "identitystore:Create*",
      "identitystore:Delete*",
      "identitystore:Update*",
      "sso-directory:*",
      "sso:Associate*",
      "sso:Attach*",
      "sso:Create*",
      "sso:Delete*",
      "sso:Detach*",
      "sso:Disassociate*",
      "sso:Provision*",
      "sso:Put*",
      "sso:Update*",
    ]
    resources = ["*"]
  }
}
