# Everything this stack needs from the base setup is discovered here rather
# than committed. That is the whole reason this repository can be public.
#
# Accounts are matched on NAME and groups on DISPLAY NAME, so renaming either
# one in the base repo breaks grants here.
#
# The check blocks below add a readable explanation, but they only ever emit
# warnings: a missing account still fails the run on the index into
# local.account_ids, and a missing group fails on the data source lookup. Read
# the warning for the cause, not the error.

data "aws_ssoadmin_instances" "this" {}

data "aws_organizations_organization" "this" {}

locals {
  sso_instance_arn  = try(tolist(data.aws_ssoadmin_instances.this.arns)[0], "")
  identity_store_id = try(tolist(data.aws_ssoadmin_instances.this.identity_store_ids)[0], "")

  # Account name -> account ID, plus `management` as a reserved alias for the
  # organization's management account. That account's real name is specific to
  # the organization and would otherwise have to be committed here, so it is
  # resolved from the API instead.
  #
  # These IDs are not marked sensitive, so they appear in full in plan output.
  # Keeping the plan out of the public Actions log is what protects them: see
  # the Summarize step in deploy.yaml.
  account_ids = merge(
    {
      for account in data.aws_organizations_organization.this.accounts :
      account.name => account.id
    },
    {
      management = data.aws_organizations_organization.this.master_account_id
    },
  )

  # Every account and group referenced by var.grants.
  granted_accounts = keys(var.grants)

  granted_groups = distinct(flatten([
    for account, groups in var.grants : keys(groups)
  ]))
}

check "sso_instance_exists" {
  assert {
    condition     = local.sso_instance_arn != "" && local.identity_store_id != ""
    error_message = "No IAM Identity Center instance found in ${var.region}. The base repo must be applied first."
  }
}

# Only accounts are checked. A missing group surfaces as a data source error on
# aws_identitystore_group below, which already names the group it could not find.
check "granted_accounts_exist" {
  assert {
    condition = alltrue([
      for name in local.granted_accounts : contains(keys(local.account_ids), name)
    ])
    error_message = "grants references an account that does not exist in the organization. Account names must match the base repo's member_accounts exactly."
  }
}

# Groups are created by the base repo. Looking them up rather than creating
# them keeps the dependency one-way.
data "aws_identitystore_group" "this" {
  for_each = toset(local.granted_groups)

  identity_store_id = local.identity_store_id

  alternate_identifier {
    unique_attribute {
      attribute_path  = "DisplayName"
      attribute_value = each.value
    }
  }
}
