# One instance per (account, group, permission set). The for_each key uses the
# account name, not its ID, so instance addresses stay readable and no ID
# appears in a plan address.

locals {
  assignments = {
    for item in flatten([
      for account, groups in var.grants : [
        for group, permission_sets in groups : [
          for permission_set in permission_sets : {
            account        = account
            group          = group
            permission_set = permission_set
          }
        ]
      ]
    ]) :
    "${item.account}-${item.group}-${item.permission_set}" => item
  }
}

resource "aws_ssoadmin_account_assignment" "this" {
  for_each = local.assignments

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.permission_set].arn
  target_id          = local.account_ids[each.value.account]
  target_type        = "AWS_ACCOUNT"
  principal_id       = data.aws_identitystore_group.this[each.value.group].group_id
  principal_type     = "GROUP"
}
