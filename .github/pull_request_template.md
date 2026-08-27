| Status            | Type                                       | Summary       |
|-------------------|--------------------------------------------|---------------|
| Ready/WIP/Blocked | Access request/Policy change/Refactor/Docs | One line      |

## What access, and why

<!--
Be specific about the AWS component and what you need to do with it.

Good: "Developers need to read SQS queue attributes in Development to debug the
       ingestion retry path."
Weak: "Need SQS access."

Include the task this unblocks. If it is temporary, say when it can go.
-->

## Changed

- [ ] `policies.tf` — actions on an existing permission set
- [ ] `variables.tf` → `permission_sets` — new or modified permission set
- [ ] `variables.tf` → `grants` — a group gained or lost access on an account
- [ ] Docs only

## Least privilege

<!-- Actions added, and why a narrower scope would not work. -->

## Checklist

- [ ] `terraform fmt -recursive`, `terraform validate` and `tflint` pass locally
- [ ] No account ID, email, personal name or bucket name in this diff
- [ ] Accounts and groups referenced by name only
- [ ] No new `Allow` on `iam:*`, `sts:AssumeRole`, `organizations:*` or `s3:*` without an explanation above
- [ ] Plan summary shows **0 to destroy**, or the destroys are explained above

<!--
Merging applies this to AWS. Read the plan summary on the checks tab; the full
plan is in the run's `plan` artifact.

Adding a person to a group is not possible here — that lives in the private base
repo. Ask a code owner.
-->
