# The permission sets themselves. Every IAM policy behind them is authored in
# ./modules/policies, which returns one finished inline policy per set.
#
# The split is deliberate: this file is resource wiring, that module is policy
# authoring. It is also why the module can be reorganized freely — it creates no
# resources, only data sources, so nothing in it has a presence in state.
module "policies" {
  source = "./modules/policies"

  permission_sets            = var.permission_sets
  region                     = var.region
  role_boundary_policy_name  = var.role_boundary_policy_name
  demo_app_prefix            = var.demo_app_prefix
  demo_app_region            = var.demo_app_region
  transform_agents_prefix    = var.transform_agents_prefix
  transform_container_prefix = var.transform_container_prefix
  edge_ai_prefix             = var.edge_ai_prefix
}

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

resource "aws_ssoadmin_permission_set_inline_policy" "this" {
  for_each = var.permission_sets

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.key].arn
  inline_policy      = module.policies.inline_policies[each.key]

  # Identity Center caps a permission set's inline policy at 10,240 bytes,
  # counting non-whitespace only, and the merged document is easily large enough
  # to reach it — the region lockdown alone is ~600 bytes before a set's own
  # statements. Without this the overflow surfaces as an opaque
  # ValidationException from PutInlinePolicyToPermissionSet at apply time, after
  # the earlier sets have already been written.
  #
  # When this trips, collapse an enumerated action list on an already
  # prefix-scoped resource to service:* rather than dropping permissions. The
  # prefix is what contains those statements, not the verb list.
  lifecycle {
    precondition {
      condition     = length(replace(module.policies.inline_policies[each.key], "/\\s/", "")) <= 10240
      error_message = "Inline policy for permission set '${each.key}' is ${length(replace(module.policies.inline_policies[each.key], "/\\s/", ""))} non-whitespace bytes, over the 10240 limit."
    }
  }
}
