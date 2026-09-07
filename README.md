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

Because the lookups match on names, **account names, group display names and the
permissions boundary name are the interface between the two repositories.**

The boundary is the third entry and the newest. `var.role_boundary_policy_name`
defaults to `DelegatedRoleBoundary`, and the permission sets that create IAM roles
require it by ARN pattern at `iam:CreateRole`. The base repository creates it in
every account, because this stack has no `iam:CreatePolicy` and only ever runs
against the management account — it can neither create the policy nor reach the
member accounts to do so.

Two consequences, for all three kinds of name:

1. **The base repository always goes first.** An account or group has to exist in
   AWS before you can reference it here. Reference something that does not exist
   and the run fails during lookup.

2. **A rename in the base repository breaks grants here.** Coordinate it: rename
   there, then here, in the same window. Renaming the boundary is the worst of
   the three: every `iam:CreateRole` in the affected sets starts failing with an
   explicit deny, and nothing in a plan here will predict it.

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

## What exists today

Six permission sets. Sessions are 8 hours except `AIGovernanceAdminAccess`,
which is 4. `variables.tf` is the source of truth for all of it; this table is a summary.

| Permission set | Backed by | Regions |
|---|---|---|
| `AdministratorAccess` | managed `AdministratorAccess` | `us-east-1`, `us-west-2` |
| `AIGovernanceAccess` | inline `ai_governance_access` | the 8 Americas regions |
| `AIGovernanceAdminAccess` | inline `ai_governance_admin_access` | the 8 Americas regions |
| `AWSTransformAccess` | inline `aws_transform_access` | `us-east-1`, `us-west-2` |
| `DevOpsAgentAccess` | inline `devops_agent_access` | `us-east-1`, `us-west-2` |
| `ReadOnlyAccess` | managed `ReadOnlyAccess` | `us-west-2` |

The inline documents are grouped by audience across `devops_agent.tf`,
`aws_transform.tf` and `ai_governance.tf`. `local.inline_policies` in
`locals.tf` is the mapping from set to document.

Every set — including the two managed-policy ones — also gets a region lockdown
merged into its inline policy. Global and region-agnostic services (IAM, STS,
Organizations, billing, Route 53, CloudFront, WAF, Support and others) are
exempted, or console sign-in would break everywhere.


Grants are `account name → group display name → permission set names`:

| Account | Group | Sets |
|---|---|---|
| `management` | `Administrators` | Administrator, ReadOnly |
| | `AIGovernance` | AIGovernanceAdminAccess |
| `Development` | `Administrators` | Administrator, ReadOnly |
| | `ReadOnly` | ReadOnly |
| `Production` | `Administrators` | Administrator, ReadOnly |
| `Sandbox` | `Administrators` | Administrator, ReadOnly |
| | `ReadOnly` | ReadOnly |
| | `AWSTransform` | AWSTransform |
| | `DevOpsAgent` | DevOpsAgent |
| | `AIGovernance` | AIGovernanceAccess |

Only groups are ever assigned. There are no user-level assignments, by design.

`ReadOnly` is the **baseline group**: every user in the base repo belongs to it.
It replaced the `Developers` and `Workshops` groups, which added nothing beyond
read access that this one does not. So a `ReadOnly` grant on an account now
means "everyone can look at this account".

That is why `Production` grants it to nobody. Only `Administrators` can see
production. If a wider production-read audience is needed again it wants its own
group in the base repo, because `ReadOnly` can no longer act as a gate for
anything.

`Administrators` holds exactly `AdministratorAccess` and `ReadOnlyAccess`, the
same pair on all four accounts. No specialised set is bundled into it: a cohort
set only ever reaches its own cohort, so exercising one means joining that group
in the base repo like anybody else. That keeps every row of the table above
answerable from the group name alone.

The one near-admin exception is on `management`, where the `AIGovernance`
**group** holds `AIGovernanceAdminAccess`. That is where Organizations write,
delegated administrator registration and SCP management actually work, none of
which is reachable from a member account. It is also the account SCPs do not apply
to, which is why that document denies its own escape hatches rather than relying
on a guardrail above it. See the `Deny` list on `ai_governance_admin_access` in
`ai_governance.tf`.

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
  Sandbox = {
    DevOpsAgent = ["DevOpsAgentAccess"]     # add or extend a line
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

1. Open the `policy_<name>.tf` file for the document that backs the set. The
   mapping is `local.inline_policies` in `locals.tf`, which is keyed by
   permission set name — so `DevOpsAgentAccess` resolves to
   `devops_agent_access`, in `devops_agent.tf`.
2. Add a statement, or actions to an existing one. Keep the narrowest verbs that
   do the job — prefer `sqs:GetQueueAttributes` over `sqs:*`.
3. Run the loop and open the pull request.

`AdministratorAccess` and `ReadOnlyAccess` use AWS managed policies, so there is
no document to edit for those.

Three things to check before assuming a new action works. The region lockdown is
merged into every set, so the action still only works in that set's approved
regions. And `role_creation_guardrail`, also merged into every set except
`AdministratorAccess`, denies IAM user creation and permissions boundary removal
outright.

If the action you are adding is `iam:CreateRole`, read the next section first.

### Grant a set the ability to create IAM roles

`iam:CreateRole` needs a separate statement from the other role writes, because
the `iam:PermissionsBoundary` condition key only exists on the `CreateRole` call
itself. Putting the condition on a statement that also carries
`iam:AttachRolePolicy` would deny that instead — the key is absent there, so the
condition can never match.

```hcl
statement {
  sid       = "MyStackCreateRoleWithBoundary"
  effect    = "Allow"
  actions   = ["iam:CreateRole"]
  resources = ["arn:aws:iam::*:role/my-prefix-*"]

  condition {
    test     = "ArnLike"
    variable = "iam:PermissionsBoundary"
    values   = [local.role_boundary_arn_pattern]
  }
}
```

The boundary is why this matters. `iam:AttachRolePolicy`'s resource is the *role*,
not the policy being attached, so a set that can create a role in its prefix and
attach a policy to it can attach `AdministratorAccess` and assume it. `iam:*` and
`sts:*` are exempt from the region lockdown and no SCP covers it. Requiring the
boundary at creation caps whatever the new role can do, and the guardrail stops
the boundary being stripped afterwards.

The boundary policy itself is created by the **base repository**, in every
account. See `role_boundary_policy_name` in `variables.tf`.

### The 10,240-byte cap

Identity Center caps a permission set's inline policy at 10,240 bytes, counting
non-whitespace only. Every set carries the region lockdown and the role-creation
guardrail on top of its own document, so the budget is tighter than it looks.

`AWSTransformAccess` is the set that runs into it. It carries four stacks - the
AWS Transform service, the fbctf app being modernised, transform-agents and
transform-containers - and without the collapses below it does not fit.

It stays one set deliberately: a second set would put two roles in the SSO portal
and the cohort would have to pick the right one mid-demo. Fitting under the cap
instead means collapsing enumerated action lists to `service:*`, which is a real
widening. The collapses, and why each is contained:

| Statement | Granted as | Contained by |
|---|---|---|
| `AWSTransformService` | `transform:*` | the service this set exists to operate, granted on Sandbox only |
| `AWSTransformSourceConnections` | `codeconnections:*` | one service, and the handshake half is unscoped anyway |
| `AWSTransformStacks` | `cloudformation:*` | the `stack/AWSTransform*/*` name prefix |
| `TransformAgentsBedrock` | `bedrock:*` | the region lockdown; the widest of the five |
| `ServiceLinkedRoles` | `iam:CreateServiceLinkedRole` on a path | IAM itself: a service-linked role's trust and policies are service-owned |

No IAM write statement is collapsed. `iam:*` on a role name prefix would let a
holder create a role there and attach anything to it, so those keep their
enumerated verbs.

A `lifecycle` precondition on `aws_ssoadmin_permission_set_inline_policy` fails the
plan with the actual byte count when a set goes over. Trust it: without it the
overflow arrives as an opaque `ValidationException` from AWS partway through an
apply, after earlier sets have already been written.

If you hit it again, weigh a second set against more collapsing. There is not much
left here that can be collapsed without touching IAM.

### Permissions boundaries are currently off

`role_plumbing.tf` can require every role a permission set creates to carry the
`DelegatedRoleBoundary` boundary, which is what stops a scope that can create a
role in its prefix from attaching `AdministratorAccess` to it and assuming it.
`require_boundary` is `false` on every scope today.

It has to be, because requiring the boundary only works if whatever creates the
role sets it. The AWS Transform CodeBuild execution role comes from a
CloudFormation template the service generates, with no `PermissionsBoundary`
property and no way for us to add one, so requiring it denies `iam:CreateRole` and
the demo cannot run. The cohort's own stacks (fbctf, transform-agents,
transform-containers, the DevOps Agent demos) could set it but do not.

What contains those scopes meanwhile: the region lockdown,
`DenyAdminPolicyAttachment` in `shared.tf`, and the guardrail's denial of boundary
stripping and IAM user creation. That is genuinely weaker - `iam:PutRolePolicy` on
the prefix still allows an inline policy wider than the creator holds - and it is a
deliberate trade.

To close it for a scope: set `permissions_boundary` on every `aws_iam_role` in that
stack, then flip `require_boundary` to `true`.

### Create a new permission set

Two steps, both in this repository:

1. Write the policy document in a new `policy_<name>.tf`.
2. Register it in `local.inline_policies` in `locals.tf`, keyed by the permission
   set's name, and add the entry to `permission_sets` in `variables.tf`:

   ```hcl
   # locals.tf
   DataAnalystAccess = data.aws_iam_policy_document.data_analyst_access.json

   # variables.tf
   DataAnalystAccess = {
     description      = "Query Athena and read the data lake"
     session_duration = "PT8H"
   }
   ```

Nothing points at the document by key: the set's own name is the link. A set that
ends up in neither `local.inline_policies` nor with a `managed_policy_arn` fails a
precondition in `permission_sets.tf` rather than silently provisioning with no
permissions.

Skip step 1 if an AWS managed policy is enough — just set `managed_policy_arn`
instead.

A permission set with no grant does nothing, so this is safe to merge on its own
and grant later.

### Widen a permission set to another region

Set `allowed_regions` on it in `permission_sets`:

```hcl
AWSTransformAccess = {
  description     = "..."
  allowed_regions = ["us-west-2", "us-east-1"]
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

## Things that break access

| Action | Effect |
|---|---|
| Renaming a key in `permission_sets` | `name` is immutable in AWS, so the set is destroyed and recreated. Every assignment pointing at it is dropped and everyone holding it loses access until it is reprovisioned |
| Renaming an account or group in the base repository | Lookups here match on those names, so every grant referencing the old name breaks |
| Adding an action already covered by a `Deny` | The `Deny` wins. `role_creation_guardrail` denies IAM user creation and boundary removal in every set |
| Merging a plan with unexplained destroys | Each destroyed assignment is somebody's access |

The plan summary flags a non-zero destroy count for exactly this reason. Read the
artifact before approving.

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
`backend.tf`, since none is environment-specific. Only the bucket and key are
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
from `backend.tf`:

```sh
terraform init \
  -backend-config="bucket=<bucket from org_pipeline_state_locations>" \
  -backend-config="key=aws-access/terraform.tfstate"
```

That bucket is shared with the base stack, which keeps its own state under
different prefixes. Do not point `key` anywhere outside `aws-access/` — the
role's policy is scoped to that prefix.

## Working with names

This repository is public, so what gets committed matters.

Never commit: AWS account IDs, email addresses, personal names, or the state
bucket and key. Accounts and groups are referenced by name and resolved at plan
time; backend wiring comes from repository secrets. `.gitignore` covers
`backend.conf`, every `*.tfvars`, state, and plan files, and deliberately has no
negation patterns.

Names of resources the policies *grant on* are fine to commit — they are targets,
not credentials. Three are committed as variable defaults today:
`demo_app_prefix` and `demo_app_region`. If a new policy
needs a resource name to scope to, add a variable for it rather than inlining the
string, so every such name stays visible in one place.

Every variable runs on its committed default. The workflow sets no `TF_VAR_*` and
passes no `-var-file`, so `variables.tf` is the whole desired state.

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
| An allowed action is still refused | Wrong region for that set, or an explicit `Deny` covers it | Check `allowed_regions`, then the `Deny` statements in the `policies_*.tf` files |

## Reference

### Layout

File names follow the Terraform style guide: `terraform.tf` for version
constraints, `backend.tf` for the backend, `providers.tf` for the provider,
`locals.tf` for values shared across files, and the rest split by concern.

The root is resource wiring. Every IAM policy is authored in
`modules/policies`, and each policy file is named after the permission set it
backs.

```
terraform.tf         required_version and required_providers
backend.tf           S3 backend (bucket and key passed at init)
providers.tf         the aws provider and its default_tags
lookups.tf           discovers accounts, groups and the SSO instance from AWS
variables.tf         permission_sets and grants — the reviewed desired state
permission_sets.tf   the sets, their attachments, and the module call
assignments.tf       group → account → permission set
outputs.tf

modules/policies/
├── terraform.tf              provider requirements for the module
├── variables.tf              the prefixes and names the policies scope to
├── locals.tf                 permission set → document mapping, and the merge
├── outputs.tf                one finished inline policy per set
├── shared.tf                 merged into every set: region lockdown + guardrail
├── role_plumbing.tf          CreateRole / PassRole / service-linked, per scope
├── devops_agent.tf           DevOpsAgentAccess
├── aws_transform.tf          AWSTransformAccess
└── ai_governance.tf          AIGovernanceAccess, AIGovernanceAdminAccess
```

Each document is the snake_case of the set it backs, so
`local.inline_policies` reads as an identity map and there is nothing to look up:
`AIGovernanceAccess` is `ai_governance_access`, in `ai_governance.tf`.

Two files are not named after a set because they do not belong to one.
`shared.tf` holds the region lockdown and the role-creation guardrail, both merged
into every set. `role_plumbing.tf` generates the `iam:CreateRole`, `iam:PassRole`
and `iam:CreateServiceLinkedRole` statements from one table of scopes, so a stack
that manages its own roles is an entry in that table rather than three statements
copied into a policy file.

The module creates **no resources** — every block in it is a data source the AWS
provider renders locally. That is what makes it safe to reorganize: there is
nothing in state to move, and the only thing that can change is the rendered JSON.

Terraform `>= 1.10.0`, for `use_lockfile` in the backend. AWS provider `~> 6.0`,
with the exact version pinned in `.terraform.lock.hcl`. State locking is
S3-native; there is no DynamoDB table.

### Variables

| Name | Purpose | Default |
|---|---|---|
| `permission_sets` | The available access levels | the six sets above |
| `grants` | Account name → group name → permission sets | the table above |
| `region` | Identity Center region and the default region lockdown | `us-west-2` |
| `demo_app_prefix` | Resource prefix scoping the demo stack | `fbctf` |
| `demo_app_region` | Region for the partner demo web app | `us-east-1` |
| `role_boundary_policy_name` | Permissions boundary required at `iam:CreateRole`, created by the base repo | `DelegatedRoleBoundary` |
| `transform_agents_prefix` | Resource prefix scoping the transform-agents PoC | `transform-agents` |
| `transform_container_prefix` | Resource prefix scoping the transform-containers PoC | `transform-containers` |

### Outputs

`permission_set_arns` — permission set name to ARN.

`assignments` — a sorted list of every `<account>-<group>-<permission set>` in
effect. It is derived from `grants`, not from AWS, so it shows what a pull request
declares rather than what is actually provisioned. It will not reveal drift.

## License

MIT. See [LICENSE](LICENSE).
