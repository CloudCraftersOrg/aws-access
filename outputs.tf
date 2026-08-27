output "permission_set_arns" {
  description = "Permission set name to ARN."
  value       = { for name, set in aws_ssoadmin_permission_set.this : name => set.arn }
}

# Useful for reviewing what a pull request actually changed.
output "assignments" {
  description = "Sorted assignments, as <account>-<group>-<permission set>."
  value       = sort(keys(local.assignments))
}
