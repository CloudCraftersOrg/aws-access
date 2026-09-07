# Alphabetical, per the Terraform style guide.

# Useful for reviewing what a pull request actually changed. Derived from
# var.grants rather than from AWS, so it shows what this configuration declares,
# not what is currently provisioned: it will not reveal drift.
output "assignments" {
  description = "Sorted assignments, as <account>-<group>-<permission set>."
  value       = sort(keys(local.assignments))
}

output "permission_set_arns" {
  description = "Permission set name to ARN."
  value       = { for name, set in aws_ssoadmin_permission_set.this : name => set.arn }
}
