# One output: the finished inline policy per permission set, ready to hand to
# aws_ssoadmin_permission_set_inline_policy.
#
# The merge lives here rather than in the root because it is policy composition,
# not resource wiring: which documents a set gets, and in what combination, is the
# same kind of decision as what is inside them. The root keeps the resource and
# the 10,240-byte precondition that guards it.
#
# AWS allows one inline policy per permission set, so up to three documents are
# collapsed into one: the set's region lockdown, the role-creation guardrail, and
# the set's own document if it has one. compact() drops the placeholders, so a set
# backed only by an AWS managed policy still receives the lockdown and guardrail.

output "inline_policies" {
  description = "Permission set name => merged inline policy JSON."
  value = {
    for name, doc in data.aws_iam_policy_document.permission_set_inline :
    name => doc.json
  }
}
