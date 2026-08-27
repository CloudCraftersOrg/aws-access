# AWS access and permissions

This is the **permissions repository**. It decides what people can do in AWS:
the permission sets available in IAM Identity Center, the IAM policies behind
them, and which group gets which set on which account.

It is a complete Terraform stack with its own state and its own pipeline. A pull
request here is the whole operation — the plan runs on the pull request, and
merging applies it to AWS. Nothing else needs to be touched or released.

It is public so pull requests get GitHub rulesets at no cost. It contains no AWS
account IDs, no email addresses and no personal names: accounts and groups are
referred to by name, and the IDs behind those names are looked up from AWS when
Terraform runs. It does commit a few resource *names* the policies grant on — a
state bucket name and a demo app prefix — which are targets rather than
credentials. See [Working with names](#working-with-names).

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

State lives in the same S3 bucket as the base stack, under the `aws-access/` key
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

That indirection is what keeps account IDs out of this repository. `management` is
a reserved account key, resolved to the organization's management account, so its
real name does not have to be committed either.

### The contract is names

Because the lookups match on names, **account names and group display names are
the interface between the two repositories.** Two consequences:

1. **The base repository always goes first.** An account or group has to exist in
   AWS before you can reference it here. Reference something that does not exist
   and the run fails during lookup.

2. **A rename in the base repository breaks grants here.** Coordinate it: rename
   there, then here, in the same window.

Two `check` blocks in `lookups.tf` explain those failures in plain language, but
they only ever emit **warnings** — a `check` cannot fail a run. The run still
fails on the underlying error: an index error into `local.account_ids` for a
missing account, or a data source error for a missing group. Read the warning for
the cause, not the error.

### What can and cannot be done here

Can: create and change permission sets, change the IAM policies inside them,
grant and revoke a group's access on an account.

Cannot: create a user, delete a user, or change who is in a group. That is
personal data and it stays in the base repository. The IAM role this stack
assumes is deliberately **read-only** on the identity store, so this is enforced
by AWS, not by convention. It is also denied `sso:DeleteInstance`, since deleting
the instance would wipe every permission set and assignment in the organization.

Also cannot: change SCPs. They live in the base repository, so this stack cannot
raise its own ceiling — a grant here is still capped by guardrails it has no
permission to edit.

### If you need to be added to a group

Open an issue or ask a code owner. It is not possible from here, by design.

---

## What exists today

Five permission sets, all with an 8-hour session:

| Permission set | Backed by | Regions |
|---|---|---|
| `AdministratorAccess` | managed `AdministratorAccess` | `us-west-2` |
| `ReadOnlyAccess` | managed `ReadOnlyAccess` | `us-west-2` |
| `PowerUserAccess` | inline `power_user_access` | `us-west-2` |
| `WorkshopOnlyAccess` | inline `infra_modify_only` | `us-west-2` |
| `AWSTransformAccess` | inline `partner_demo_access` | `us-west-2`, `us-east-1` |

Every set — including the two managed-policy ones — also gets a region lockdown
merged into its inline policy. Global and region-agnostic services (IAM, STS,
Organizations, billing, Route 53, CloudFront, WAF, Support and others) are
exempted, or console sign-in would break everywhere.

> `PowerUserAccess` here is **not** the AWS managed `PowerUserAccess` policy. It
> is a read-only observability set whose only non-read action is invoking a
> deployed agent runtime. The name is historical and misleading; read
> `policies.tf` before assuming what it grants.
>
> `WorkshopOnlyAccess` is read plus update and tag, never create or destroy, with
> an explicit `Deny` on roughly 35 `Create*`/`Delete*` actions as a second layer.

Grants are `account name → group display name → permission set names`:

| Account | Group | Sets |
|---|---|---|
| `management` | `Administrators` | Administrator, PowerUser, ReadOnly |
| `Development` | `Administrators` | Administrator, PowerUser, ReadOnly |
| | `Developers` | PowerUser |
| | `InfraModifiers` | WorkshopOnly |
| `Production` | `Administrators` | Administrator, PowerUser, ReadOnly |
| | `Developers` | PowerUser |
| | `InfraModifiers` | WorkshopOnly |
| | `ReadOnly` | ReadOnly |
| `Sandbox` | `Administrators` | Administrator, PowerUser, ReadOnly, AWSTransform |
| | `Workshops` | PowerUser |
| | `AWSTransform` | AWSTransform |

Only groups are ever assigned. There are no user-level assignments, by design.

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
2. The **Plan and Apply** check assumes the AWS role and plans. It writes the
   add/change/destroy counts to the job summary, and uploads the plan as a run
   artifact named `plan`.
3. Download that artifact and read it. Confirm **0 to destroy** unless you meant
   otherwise.
4. A code owner approves, you merge, and the post-merge run plans again and
   applies.

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
accounts and groups in the base repository, permission sets in this file. Both
are validated, so a typo fails CI rather than reaching AWS.

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

`AdministratorAccess` and `ReadOnlyAccess` use AWS managed policies, so there is
no document to edit for those.

Two things to check before assuming a new action works. The region lockdown is
merged into every set, so the action still only works in that set's approved
regions. And `WorkshopOnlyAccess` carries an explicit `Deny` on create and
destroy verbs, which beats any `Allow` you add — widen that list deliberately or
not at all.

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

### Widen a permission set to another region

Set `allowed_regions` on it in `permission_sets`:

```hcl
AWSTransformAccess = {
  description       = "..."
  inline_policy_key = "partner_demo_access"
  allowed_regions   = ["us-west-2", "us-east-1"]
}
```

The default is `[var.region]`. The lockdown is built per set, so this opens the
extra region for that one set only. Managed-policy sets need it too if they are
meant to work outside `var.region`.

### Remove access

Delete the entry from `grants` and merge. The plan will show a destroy, which is
expected here — that destroy *is* the revocation. Everything else about a destroy
in the plan should be treated as suspicious.

Removing a permission set entirely means deleting it from `permission_sets` and
removing every grant referencing it in the same pull request.

### Change how long a session lasts

`session_duration` on the set, as an ISO-8601 duration such as `PT8H` or
`PT1H30M`. There is a validation, but it is loose enough that a degenerate value
like `PT` passes CI and is rejected by AWS at apply. Give it a real duration.

---

## Things that break access

| Action | Effect |
|---|---|
| Renaming a key in `permission_sets` | `name` is immutable in AWS, so the set is destroyed and recreated. Every assignment pointing at it is dropped and everyone holding it loses access until it is reprovisioned |
| Renaming an account or group in the base repository | Lookups here match on those names, so every grant referencing the old name breaks |
| Adding an action already covered by a `Deny` | The `Deny` wins. `WorkshopOnlyAccess` denies create and destroy verbs outright |
| Merging a plan with unexplained destroys | Each destroyed assignment is somebody's access |

The plan summary flags a non-zero destroy count for exactly this reason. Read the
artifact before approving.

---

## Stages

| Job | Pull request | Merge to `main` |
|---|---|---|
| `Lint` | `fmt -check`, `validate`, `tflint`. No AWS access | same |
| `Plan and Apply` | assume role → `init` → `plan` → counts in the job summary + `plan` artifact | same, then `apply` |

Both job names are literal, so they are what a required-status-check rule has to
match.

Three things about that pipeline are worth knowing before you rely on it:

**The pull request's plan is a preview, not the artifact that gets applied.** The
saved `tfplan` does not cross runs. The post-merge `push` run does its own `init`
and `plan` and applies that. If `main` moved, or AWS drifted, the applied plan is
not byte-for-byte the one that was reviewed.

**The full plan never appears in the log or in a PR comment.** Actions logs on a
public repository are readable by anyone, and plan output resolves account IDs
and ARNs. Nothing in this stack is marked `sensitive`, so that protection is
entirely procedural: the plan is only ever written to a file. Note that the
`plan` artifact is `plan.json` from `terraform show -json` — machine-readable,
not rendered plan text — and it is downloadable by anyone who can read the repo.
The binary `tfplan` is not uploaded, so the artifact cannot be re-rendered as a
readable plan.

**Fork pull requests cannot reach AWS.** GitHub issues no OIDC token for them, so
the `Plan and Apply` job fails on a fork by design. `Lint` still runs and is the
useful signal. The trigger is `pull_request`, never `pull_request_target`.

The workflow has no path filters, so every pull request runs it. It declares no
GitHub `environment`, so there is no manual approval gate: merging applies.

---

## Setup

This stack needs an IAM role to assume, created by the base repository's
bootstrap stack in the management account, which lists this repository in
`org_pipeline_repos`. It does **not** get its own state bucket: it writes to the
management account's existing bucket under the `aws-access/` key prefix, and the
role is scoped to that prefix so it cannot read the base stack's state.

Take this repository's entry from the `org_pipeline_role_arns` and
`org_pipeline_state_locations` outputs of bootstrap — both are keyed by repo name
— then set three values under **Settings → Secrets and variables → Actions**.
They are split between Variables and Secrets, and the workflow reads them by
exactly these kinds:

| Name | Kind | Value |
|---|---|---|
| `AWS_ROLE_ARN` | Variable | the role ARN from bootstrap |
| `TF_STATE_BUCKET` | Secret | the `bucket` from `org_pipeline_state_locations` |
| `TF_STATE_KEY` | Secret | the `key` from it, i.e. `aws-access/terraform.tfstate` |

All three are required; `init` fails without the two secrets. The role ARN is a
Variable because it is not sensitive — only its trust policy controls who can
assume it, and IAM enforces that. The bucket and key are Secrets to keep the
bucket name out of a public repository.

`region`, `encrypt` and `use_lockfile` are not configurable — they are in
`config.tf`, since none is environment-specific. Only the bucket and key are
passed to `terraform init`.

The key must stay under the `aws-access/` prefix. The IAM role's S3 policy is
scoped to a prefix named after this repository, so pointing the key elsewhere
breaks access to the state — `terraform init` fails with a 403 on `HeadObject`.

Then add a ruleset on `main`:

- Require a pull request before merging, at least one approval
- Require review from Code Owners
- Dismiss stale approvals when new commits are pushed
- Require the `Lint` and `Plan and Apply` checks
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

`tflint` uses the bundled Terraform ruleset only, so it needs no plugin download
and no `tflint --init`.

To run against real state, pass the bucket and key. Region and encryption come
from `config.tf`:

```sh
terraform init \
  -backend-config="bucket=<bucket from org_pipeline_state_locations>" \
  -backend-config="key=aws-access/terraform.tfstate"
```

That bucket is shared with the base stack, which keeps its own state under
different prefixes. Do not point `key` anywhere outside `aws-access/` — the
role's policy is scoped to that prefix.

---

## Working with names

This repository is public, so what gets committed matters.

Never commit: AWS account IDs, email addresses, personal names, or the state
bucket and key. Accounts and groups are referenced by name and resolved at plan
time; backend wiring comes from repository secrets. `.gitignore` covers
`backend.conf`, every `*.tfvars`, state, and plan files, and deliberately has no
negation patterns.

Names of resources the policies *grant on* are fine to commit — they are targets,
not credentials. Three are committed as variable defaults today:
`state_bucket_names`, `demo_app_prefix` and `demo_app_region`. If a new policy
needs a resource name to scope to, add a variable for it rather than inlining the
string, so every such name stays visible in one place.

Every variable runs on its committed default. The workflow sets no `TF_VAR_*` and
passes no `-var-file`, so `variables.tf` is the whole desired state.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `No IAM Identity Center instance found` warning, then errors on every SSO resource | The base repository has not been applied, or the instance is in another region | Apply the base repository first. The `check` only warns; the errors below it are the real failure |
| `grants references an account that does not exist` warning, then an index error | Account name typo, or the account is not created yet | Match `member_accounts` in the base repository exactly, and merge there first |
| Plan fails looking up a group | The group does not exist yet, or was renamed. There is no `check` for groups, so this surfaces straight from the data source | Add or rename it in the base repository first |
| `Every permission set in grants must be declared in permission_sets` | Typo in a grant | Fix the name; this is CI catching it before AWS does |
| `Plan and Apply` fails on a fork pull request | Forks get no OIDC token, by design | Push a branch in this repository instead |
| `error assuming role: AccessDenied` | `AWS_ROLE_ARN` unset, or bootstrap has not created the role | Check the variable and the bootstrap output |
| `init` fails with 403 on `HeadObject` | `TF_STATE_KEY` points outside the `aws-access/` prefix | Put the key back under `aws-access/` |
| Plan wants to replace a permission set | A key in `permission_sets` was renamed | Revert the rename, or accept the access interruption deliberately |
| A user has no access despite the grant | They are not in the group | Membership lives in the base repository |
| An allowed action is still refused | Wrong region for that set, or an explicit `Deny` covers it | Check `allowed_regions`, then the `Deny` statements in `policies.tf` |

---

## Reference

### Layout

```
config.tf            versions, provider, S3 backend (bucket and key passed at init)
lookups.tf           discovers accounts, groups and the SSO instance from AWS
variables.tf         permission_sets and grants — the reviewed desired state
policies.tf          inline IAM policies + the per-set region lockdown
permission_sets.tf   permission sets and their policy attachments
assignments.tf       group → account → permission set
outputs.tf
```

Terraform `>= 1.10.0`, for `use_lockfile` in the backend. AWS provider `>= 5.0`.
State locking is S3-native; there is no DynamoDB table.

### Variables

| Name | Purpose | Default |
|---|---|---|
| `permission_sets` | The available access levels | the five sets above |
| `grants` | Account name → group name → permission sets | the table above |
| `region` | Identity Center region and the default region lockdown | `us-west-2` |
| `state_bucket_names` | Buckets the modify-only set may read/write | `["cloudcrafters-workshop-2026-tfstate"]` |
| `demo_app_prefix` | Resource prefix scoping the demo stack | `fbctf` |
| `demo_app_region` | Region for the partner demo web app | `us-east-1` |

### Outputs

`permission_set_arns` — permission set name to ARN.

`assignments` — a sorted list of every `<account>-<group>-<permission set>` in
effect. It is derived from `grants`, not from AWS, so it shows what a pull request
declares rather than what is actually provisioned. It will not reveal drift.

## License

MIT. See [LICENSE](LICENSE).
