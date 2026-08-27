resource "aws_ssoadmin_permission_set" "this" {
  for_each = var.permission_sets

  name             = each.key
  description      = each.value.description
  instance_arn     = local.sso_instance_arn
  session_duration = each.value.session_duration
}

resource "aws_ssoadmin_managed_policy_attachment" "this" {
  for_each = {
    for name, config in var.permission_sets :
    name => config if config.managed_policy_arn != null
  }

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.key].arn
  managed_policy_arn = each.value.managed_policy_arn
}

# This is where a permission set and its policy actually meet. AWS SSO allows one
# inline policy per set, so the region lockdown and the set's own document are
# merged into a single document. compact() drops the placeholder for sets that
# carry only a managed policy, so those still get the region restriction.
#
# Which document each set resolves to is the table at the top of policies.tf.
data "aws_iam_policy_document" "permission_set_inline" {
  for_each = var.permission_sets

  source_policy_documents = compact([
    data.aws_iam_policy_document.region_restriction[each.key].json,
    each.value.inline_policy_key != null ? local.inline_policies[each.value.inline_policy_key] : "",
  ])
}

resource "aws_ssoadmin_permission_set_inline_policy" "this" {
  for_each = var.permission_sets

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.key].arn
  inline_policy      = data.aws_iam_policy_document.permission_set_inline[each.key].json
}
