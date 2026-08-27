# AWS access and permissions

This is the **permissions repository**. It decides what people can do in AWS:
the permission sets available in IAM Identity Center, the IAM policies behind
them, and which group gets which set on which account.

It is a complete Terraform stack with its own state and its own pipeline. A pull
request here is the whole operation — the plan runs on the pull request, and
merging applies it to AWS. Nothing else needs to be touched or released.

It is public so pull requests get GitHub rulesets at no cost, and it is safe to
be public because it contains no AWS account IDs, no email addresses, no personal
names and no bucket names. Accounts and groups are referred to by name, and the
IDs behind those names are looked up from AWS when Terraform runs.

---

## How the two repositories fit together

The foundation lives in a separate private **base repository**: the AWS
Organization, the member accounts, the Service Control Policies, and the
Identity Center directory, meaning the users, the groups, and who belongs to
which group.

### Who owns what

| | Base repository (private) | Here |
|---|---|---|
| AWS Organization, OUs, member accounts | ✅ | |
| Service Control Policies | ✅ | |
| Identity Center groups | ✅ | |
| Users, and who is in which group | ✅ | |
| CloudTrail, budgets, CI roles | ✅ | |
| **Permission sets** and their IAM policies | | ✅ |
| **Grants** (group → account → permission set) | | ✅ |

State lives in the same S3 bucket as the base stack, under a separate key
prefix. This stack's role is scoped to that prefix, so it cannot read the base
stack's state.

The base repository decides **who exists and what the ceiling is**. This one
decides **what they can do underneath it**.

### Nothing is wired between them

There is no module, no shared state and no passed-in outputs. This stack finds
what it needs by querying the AWS API when it plans, in `lookups.tf`:

| Needed | Looked up by | Data source |
|---|---|---|
| Account IDs | account **name** | `aws_organizations_organization` |
| Group IDs | group **display name** | `aws_identitystore_group` |
| Identity Center instance | region | `aws_ssoadmin_instances` |

That indirection is what keeps account IDs out of this repository.

### The contract is names

Because the lookups match on names, **account names and group display names are
the interface between the two repositories.** Two consequences:

1. **The base repository always goes first.** An account or group has to exist in
   AWS before you can reference it here. Reference something that does not exist
   and the plan fails on the lookup. Two `check` blocks in `lookups.tf` turn that
   into a readable message rather than an index error.

2. **A rename in the base repository breaks grants here.** Coordinate it: rename
   there, then here, in the same window.

### What can and cannot be done here

Can: create and change permission sets, change the IAM policies inside them,
grant and revoke a group's access on an account.

Cannot: create a user, delete a user, or change who is in a group. That is
personal data and it stays in the base repository. The IAM role this stack
assumes is deliberately **read-only** on the identity store, so this is enforced
by AWS, not by convention.

Also cannot: change SCPs. They live in the base repository, so this stack cannot
raise its own ceiling — a grant here is still capped by guardrails it has no
permission to edit.

### If you need to be added to a group

Open an issue or ask a code owner. It is not possible from here, by design.

---

## Operations

Every change follows the same loop.

```sh
git checkout -b access/short-description

# edit

terraform fmt -recursive
terraform init -backend=false      # first time only, no credentials needed
terraform validate
tflint

git commit -am "feat: describe the change"
git push -u origin HEAD
```

Open a pull request, then:

1. The **Lint** check runs immediately and needs no AWS access.
2. The **Plan and apply** check assumes the AWS role and plans. It posts the
   add/change/destroy counts to the checks tab, and uploads the readable plan as
   a run artifact named `plan`.
3. Download that artifact and read it. Confirm **0 to destroy** unless you meant
   otherwise.
4. A code owner approves, you merge, and the same job applies the saved plan.

> `terraform validate` and `tflint` work locally with no credentials. `terraform
> plan` needs them, so let the pull request produce it.

### Give a group access on an account

The most common change. Edit `grants` in `variables.tf`:

```hcl
grants = {
  Development = {
    Developers = ["PowerUserAccess"]        # add or extend a line
  }
}
```

The outer key is the AWS **account name**, the inner key is the **group display
name**, and the list is permission set names. All three must already exist:
accounts and groups in the base repository, permission sets in this file.

Merging provisions the assignment. Affected users see the new role in their SSO
portal at their next sign-in; existing sessions keep their old roles until the
token expires.

### Add actions to an existing permission set

The other common change: someone needs to use a service they cannot reach yet,
with a level of access they already have.

1. Find the document in `policies.tf` that backs the permission set. The mapping
   is `inline_policy_key` on the set in `variables.tf`:

   | Permission set | Document |
   |---|---|
   | `PowerUserAccess` | `power_user_access` |
   | `WorkshopOnlyAccess` | `infra_modify_only` |
   | `AWSTransformAccess` | `partner_demo_access` |

2. Add a statement, or actions to an existing one. Keep the narrowest verbs that
   do the job — prefer `sqs:GetQueueAttributes` over `sqs:*`.
3. Run the loop and open the pull request.

Note that `AdministratorAccess` and `ReadOnlyAccess` use AWS managed policies, so
there is no document to edit for those.

Every set also gets a region lockdown merged into its inline policy, so a new
action still only works in that set's approved regions.

### Create a new permission set

Four steps, all in this repository:

1. Write the policy document in `policies.tf`.
2. Register its key in `local.inline_policies` at the top of that file.
3. Add the key to the `inline_policy_key` validation in `variables.tf`, so a typo
   fails CI instead of reaching AWS.
4. Add the entry to `permission_sets`:

   ```hcl
   DataAnalystAccess = {
     description       = "Query Athena and read the data lake"
     inline_policy_key = "data_analyst_access"
     session_duration  = "PT8H"
   }
   ```

Skip steps 1–3 if an AWS managed policy is enough — just set
`managed_policy_arn` instead.

A permission set with no grant does nothing, so this is safe to merge on its own
and grant later.

If the policy needs a resource name to scope to, add a variable for it rather
than inlining the string, so the scope is visible in one place. Names of
resources the policies *grant on* are fine to commit — they are targets, not
credentials. Backend and role configuration is the exception and stays in
repository variables.

### Widen a permission set to another region

Set `allowed_regions` on it in `permission_sets`:

```hcl
AWSTransformAccess = {
  description       = "..."
  inline_policy_key = "partner_demo_access"
  allowed_regions   = ["us-west-2", "us-east-1"]
}
```

The default is `[var.region]`. This overrides the lockdown for that one set only,
so the extra region does not open up for everybody.

### Remove access

Delete the entry from `grants` and merge. The plan will show a destroy, which is
expected here — that destroy *is* the revocation. Everything else about a destroy
in the plan should be treated as suspicious.

Removing a permission set entirely means deleting it from `permission_sets` and
removing every grant referencing it in the same pull request.

### Change how long a session lasts

`session_duration` on the set, as an ISO-8601 duration such as `PT8H` or
`PT1H30M`. Validated, so a malformed value fails CI.

---

## Things that break access

| Action | Effect |
|---|---|
| Renaming a key in `permission_sets` | `name` is immutable in AWS, so the set is destroyed and recreated. Every assignment pointing at it is dropped and everyone holding it loses access until it is reprovisioned |
| Renaming an account or group in the base repository | Lookups here match on those names, so every grant referencing the old name breaks |
| Merging a plan with unexplained destroys | Each destroyed assignment is somebody's access |

The plan summary flags a non-zero destroy count for exactly this reason. Read the
artifact before approving.

---

## Stages

| Job | Pull request | Merge to `main` |
|---|---|---|
| `Lint` | `fmt -check`, `validate`, `tflint`. No AWS access | same |
| `Plan and apply` | assume role → `init` → `plan` → counts in the job summary + `plan` artifact | same, then `apply` of the saved plan |

`apply` runs the saved plan file rather than re-planning, so what was reviewed is
what runs.

Two deliberate choices in that pipeline:

**The full plan never appears in the log or in a PR comment.** Actions logs on a
public repository are readable by anyone, and plan output resolves account IDs
and ARNs. It goes to a run artifact instead, and account IDs are additionally
wrapped in `sensitive()` in `assignments.tf` so they are redacted even there.

**Fork pull requests cannot reach AWS.** GitHub issues no OIDC token for them, so
the `Plan and apply` job fails on a fork by design. `Lint` still runs and is the
useful signal. The trigger is `pull_request`, never `pull_request_target`.

---

## Setup

This stack needs an IAM role to assume, created by the base repository's
bootstrap stack in the management account. It does **not** get its own state
bucket: it writes to the management account's existing bucket under the
`permissions/` key prefix, and the role is scoped to that prefix so it cannot
read the base stack's state.

Take the `access_repo_role_arn` and `access_repo_state_location` outputs from
bootstrap, then set these under **Settings → Secrets and variables → Actions →
Variables**:

| Variable | Value |
|---|---|
| `AWS_ROLE_ARN` | the role ARN from bootstrap |
| `TF_STATE_BUCKET` | the `bucket` from `access_repo_state_location` |
| `TF_STATE_KEY` | the `key` from it, e.g. `permissions/terraform.tfstate` |

All three are required. `region` and `encrypt` are not variables — they are in
`config.tf`, since neither is environment-specific. Only the bucket and key are
passed to `terraform init`, which is why the bucket name never appears in this
repository.

The key must stay under the `permissions/` prefix. The IAM role's S3 policy is
scoped to it, so pointing the key elsewhere breaks access to the state.

Then add a ruleset on `main`:

- Require a pull request before merging, at least one approval
- Require review from Code Owners
- Dismiss stale approvals when new commits are pushed
- Require the `Lint` and `Plan and apply` checks
- Block force pushes and branch deletion

Under **Settings → Actions**, confirm that fork pull request workflows require
approval for outside collaborators, and that the default workflow permission is
read-only.

### Working locally

`validate` and `tflint` need no backend and no credentials:

```sh
terraform init -backend=false
terraform validate
tflint
```

To run against real state, pass the bucket and key. Region and encryption come
from `config.tf`:

```sh
terraform init \
  -backend-config="bucket=<bucket from access_repo_state_location>" \
  -backend-config="key=permissions/terraform.tfstate"
```

That bucket is shared with the base stack, which keeps its own state under
different prefixes. Do not point `key` anywhere outside `permissions/` — the
role's policy is scoped to that prefix.

---

## One-time: adopting the existing resources

The permission sets and assignments already exist in AWS, created by the base
repository before the split. They have to be imported rather than created.

Run this **locally, never through CI**, and never commit the output: the import
IDs contain real account IDs and permission set ARNs, and this repository is
public. `imports.tf` is gitignored for that reason.

Only after the base repository has applied its side and forgotten the resources
from its own state:

```sh
terraform init \
  -backend-config="bucket=<bucket from access_repo_state_location>" \
  -backend-config="key=permissions/terraform.tfstate"

AWS_PROFILE=<management-account> scripts/generate-imports.sh > imports.tf
grep -c '^import {' imports.tf   # sanity-check the count before planning

terraform plan      # must show imports and ZERO creates, ZERO destroys
terraform apply

rm imports.tf
```

If the plan wants to **create** a permission set, it did not import — usually
because the base repository has not forgotten it yet, or the generator missed it.
Stop and fix that; applying would fail on a name conflict at best.

The script runs on stock macOS bash 3.2 and needs nothing installed beyond the
AWS CLI. Progress goes to stderr, so only HCL lands in `imports.tf`.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `No IAM Identity Center instance found` | The base repository has not been applied, or the instance is in another region | Apply the base repository first |
| `grants references an account that does not exist` | Account name typo, or the account is not created yet | Match `member_accounts` in the base repository exactly, and merge there first |
| Plan fails looking up a group | The group does not exist yet, or was renamed | Add or rename it in the base repository first |
| `Every permission set in grants must be declared in permission_sets` | Typo in a grant | Fix the name; this is CI catching it before AWS does |
| `Plan and apply` fails on a fork pull request | Forks get no OIDC token, by design | Push a branch in this repository instead |
| `error assuming role: AccessDenied` | `AWS_ROLE_ARN` unset, or bootstrap has not created the role | Check the variable and the bootstrap output |
| Plan wants to replace a permission set | A key in `permission_sets` was renamed | Revert the rename, or accept the access interruption deliberately |
| A user has no access despite the grant | They are not in the group | Membership lives in the base repository |

---

## Reference

### Layout

```
config.tf            versions, provider, S3 backend (values passed at init)
lookups.tf           discovers accounts, groups and the SSO instance from AWS
variables.tf         permission_sets and grants — the reviewed desired state
policies.tf          inline IAM policies + the per-set region lockdown
permission_sets.tf   permission sets and their policy attachments
assignments.tf       group → account → permission set
outputs.tf
scripts/             one-time import generator
```

### Variables

| Name | Purpose |
|---|---|
| `permission_sets` | The available access levels |
| `grants` | Account name → group name → permission sets |
| `region` | Identity Center region and the default region lockdown |
| `state_bucket_names` | Buckets the modify-only set may read/write |
| `demo_app_prefix` | Resource prefix scoping the demo stack |
| `demo_app_region` | Region for the partner demo web app |

### Outputs

`permission_set_arns`, and `assignments` — a sorted list of every
`<account>-<group>-<permission set>` in effect, which is the quickest way to see
what a pull request actually changed.

### A note on the permission set names

`PowerUserAccess` here is **not** the AWS managed `PowerUserAccess` policy. It is
a read-only observability set whose only non-read action is invoking a deployed
agent runtime. The name is historical and misleading; check `policies.tf` before
assuming what it grants.

## License

MIT. See [LICENSE](LICENSE).
