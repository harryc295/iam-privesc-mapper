# iam-privesc-mapper

Finds privilege-escalation paths in an AWS account's IAM configuration —
"this low-privilege user can become an admin in N hops" — and renders an
interactive attack-path graph plus a findings report mapped to compliance
controls.

Most cloud security tooling checks *configuration hygiene* (open S3 buckets,
unused keys, MFA off). This checks something most junior-to-mid tooling
doesn't: whether your **IAM identity graph** lets someone walk from a
low-privilege principal to `AdministratorAccess`. That's how real breaches
escalate (Capital One, the Codecov supply-chain breach, most cloud
ransomware playbooks) — config scanners don't catch it, this does.

## Quickstart (zero AWS setup)

```bash
pip install -r requirements.txt
python main.py --fixture demo/sample_account.json
# open output/report.html in a browser
```

The demo fixture is a small synthetic account with four planted escalation
paths so you can see what a finding looks like without touching AWS.

## Running against a real account

```bash
python main.py --profile my-readonly-profile
```

Needs an IAM identity with read-only IAM/STS permissions:
`iam:Get*`, `iam:List*`, `sts:GetCallerIdentity`. It makes no write calls.

**Validate it on purpose-built vulnerable infrastructure, not your real
account first.** [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat)
(Rhino Security Labs) spins up deliberately misconfigured AWS environments
for exactly this. Run a CloudGoat IAM-privesc scenario, point this tool at
the scenario's low-priv credentials profile, and confirm it finds the
intended path. Destroy the CloudGoat stack afterwards — it costs real money
left running.

## What it detects

Based on the [Rhino Security Labs AWS privilege-escalation
research](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/),
the highest-signal subset for v1:

- Self-privesc via a single dangerous IAM action: `CreatePolicyVersion`,
  `SetDefaultPolicyVersion`, `Attach{User,Role,Group}Policy`,
  `Put{User,Role,Group}Policy`, `UpdateAssumeRolePolicy`
- Credential takeover of another principal: `CreateLoginProfile`,
  `UpdateLoginProfile`, `CreateAccessKey`
- `iam:PassRole` combined with `lambda:CreateFunction` or `ec2:RunInstances`
  to run code as a more-privileged role
- Multi-hop `sts:AssumeRole` chains that reach an admin-equivalent role
  (the one check that needs graph traversal, not just a policy read)
- Baseline: principals that already have `Action:*` (CIS 1.16)

Each finding is mapped to a CIS AWS Foundations control or, where no
specific control exists for that technique, to the NIST CSF least-privilege
control family — see `iam_privesc_mapper/cis_mapping.py` for the reasoning.

## Known limitations (read before trusting a finding)

`principal_can()` approximates IAM policy evaluation: it matches Allow/Deny
statements by action (with wildcards) and **ignores Resource constraints,
Condition blocks, SCPs, and permission boundaries**. That means false
positives are possible on tightly-scoped policies. For exact confirmation
of a specific finding, call IAM's own `simulate_principal_policy` API before
treating it as ground truth — that's the natural phase-2 addition, deferred
for v1 because it costs an API call per principal/action pair and isn't
needed to demonstrate the core graph-analysis technique.

## Architecture

```
collector.py    boto3, read-only IAM enumeration -> plain-dict account model
rules.py        single/two-action privesc checks against that model
graph.py        networkx principal graph + multi-hop AssumeRole chain search
cis_mapping.py  rule_id -> compliance control mapping
report.py       string.Template + pyvis -> static HTML report (no web framework)
main.py         CLI glue
```

No database, no server, no frontend framework — the AWS account itself is
the state, and a static HTML file is the dashboard.

## Tests

```bash
python -m pytest
```

Synthetic IAM fixtures asserting each rule fires (and doesn't fire) correctly,
including the deny-overrides-allow and group-inheritance cases.

## Roadmap

- CloudTrail/GuardDuty detection rule + one-page incident-response runbook
  per finding type (closes the detect-and-respond loop)
- Multi-account scan via AWS Organizations
- Optional `simulate_principal_policy` confirmation pass to cut false positives

## License

MIT
