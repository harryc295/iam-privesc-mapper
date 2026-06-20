"""Detection rules for known AWS IAM privilege-escalation techniques.

Based on the well-known Rhino Security Labs research
(https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/).
Covers the highest-signal subset for v1, not the full list.

LIMITATION (documented, not hidden): `principal_can` approximates IAM policy
evaluation -- it checks Allow/Deny action grants via wildcard matching and
ignores Resource constraints, Condition blocks, SCPs and permission
boundaries. It will produce some false positives on tightly-scoped policies.
For exact evaluation, confirm a finding with IAM's own
`simulate_principal_policy` API before treating it as ground truth.
ponytail: good enough to catch the common real-world misconfigs this project
targets; upgrade to simulate_principal_policy if you need exact resource/condition evaluation.
"""
import fnmatch


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _matches_any(action, patterns):
    return any(fnmatch.fnmatch(action.lower(), p.lower()) for p in patterns)


def statement_allows(statement, action):
    if statement.get("Effect") != "Allow":
        return False
    not_actions = _as_list(statement.get("NotAction"))
    if not_actions:
        return not _matches_any(action, not_actions)
    return _matches_any(action, _as_list(statement.get("Action")))


def statement_denies(statement, action):
    if statement.get("Effect") != "Deny":
        return False
    return _matches_any(action, _as_list(statement.get("Action")))


def principal_can(principal: dict, account: dict, action: str) -> bool:
    docs = [p["document"] for p in principal.get("policies", [])]
    if principal.get("type") == "user":
        for gname in principal.get("groups", []):
            group = account["groups"].get(gname)
            if group:
                docs += [p["document"] for p in group["policies"]]
    statements = [s for doc in docs for s in _as_list(doc.get("Statement"))]
    if any(statement_denies(s, action) for s in statements):
        return False
    return any(statement_allows(s, action) for s in statements)


def is_admin_equivalent(principal: dict, account: dict) -> bool:
    return principal_can(principal, account, "*")


def _all_principals(account):
    yield from account["users"].items()
    yield from account["roles"].items()


def _finding(rule_id, title, severity, name, principal, target, evidence):
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "principal": name,
        "principal_type": principal["type"],
        "target": target,
        "evidence": evidence,
    }


# action, rule_id, severity, "<name> ..." sentence completing the evidence text
_SELF_PRIVESC_ACTIONS = [
    ("iam:CreatePolicyVersion", "iam-create-policy-version", "Critical",
     "can create a new default version of any customer-managed policy attached to "
     "themselves, embedding full admin permissions, then act as admin."),
    ("iam:SetDefaultPolicyVersion", "iam-set-default-policy-version", "Critical",
     "can roll an attached customer-managed policy back to a version they control "
     "(e.g. a previously-saved admin version)."),
    ("iam:AttachUserPolicy", "iam-attach-user-policy", "Critical",
     "can attach any managed policy (e.g. AdministratorAccess) directly to themselves."),
    ("iam:AttachRolePolicy", "iam-attach-role-policy", "Critical",
     "can attach any managed policy to a role they can already access, escalating that role."),
    ("iam:AttachGroupPolicy", "iam-attach-group-policy", "Critical",
     "can attach any managed policy to a group they belong to."),
    ("iam:PutUserPolicy", "iam-put-user-policy", "Critical",
     "can write an inline policy on themselves granting any permission, including full admin."),
    ("iam:PutRolePolicy", "iam-put-role-policy", "High",
     "can write an inline policy on a role they can already access, escalating that role."),
    ("iam:PutGroupPolicy", "iam-put-group-policy", "High",
     "can write an inline policy on a group they belong to."),
    ("iam:UpdateAssumeRolePolicy", "iam-update-assume-role-policy", "High",
     "can rewrite a role's trust policy to allow themselves to assume it."),
]


def rule_self_privesc_actions(account):
    findings = []
    for name, p in _all_principals(account):
        if is_admin_equivalent(p, account):
            continue  # already covered by rule_already_admin_equivalent
        for action, rule_id, severity, sentence in _SELF_PRIVESC_ACTIONS:
            if principal_can(p, account, action):
                findings.append(_finding(
                    rule_id, action, severity, name, p, target=name,
                    evidence=f"{name} has `{action}` and {sentence}",
                ))
    return findings


def rule_create_or_update_login_profile(account):
    findings = []
    for name, p in _all_principals(account):
        if is_admin_equivalent(p, account):
            continue
        for action, rule_id, label in [
            ("iam:CreateLoginProfile", "iam-create-login-profile", "set an initial console password for"),
            ("iam:UpdateLoginProfile", "iam-update-login-profile", "reset the console password of"),
        ]:
            if principal_can(p, account, action):
                for other_name, other in account["users"].items():
                    if other_name == name:
                        continue
                    findings.append(_finding(
                        rule_id, action, "High", name, p, target=other_name,
                        evidence=f"{name} has `{action}` and can {label} {other_name}, then log in as them.",
                    ))
    return findings


def rule_create_access_key(account):
    findings = []
    for name, p in _all_principals(account):
        if is_admin_equivalent(p, account):
            continue
        if not principal_can(p, account, "iam:CreateAccessKey"):
            continue
        for other_name in account["users"]:
            if other_name == name:
                continue
            findings.append(_finding(
                "iam-create-access-key", "iam:CreateAccessKey", "Critical", name, p, target=other_name,
                evidence=f"{name} has `iam:CreateAccessKey` and can mint new programmatic "
                         f"credentials for {other_name}.",
            ))
    return findings


def _admin_equivalent_roles(account):
    return [name for name, r in account["roles"].items() if is_admin_equivalent(r, account)]


def rule_pass_role_to_new_lambda(account):
    findings = []
    targets = _admin_equivalent_roles(account)
    if not targets:
        return findings
    for name, p in _all_principals(account):
        if is_admin_equivalent(p, account):
            continue
        if not (principal_can(p, account, "iam:PassRole")
                and principal_can(p, account, "lambda:CreateFunction")
                and (principal_can(p, account, "lambda:InvokeFunction")
                     or principal_can(p, account, "lambda:CreateEventSourceMapping"))):
            continue
        for role_name in targets:
            findings.append(_finding(
                "pass-role-to-new-lambda", "iam:PassRole + lambda:CreateFunction", "Critical",
                name, p, target=role_name,
                evidence=f"{name} can create a Lambda function, pass it the admin-equivalent "
                         f"role {role_name}, and invoke it to run code as that role.",
            ))
    return findings


def rule_pass_role_to_new_ec2(account):
    findings = []
    targets = _admin_equivalent_roles(account)
    if not targets:
        return findings
    for name, p in _all_principals(account):
        if is_admin_equivalent(p, account):
            continue
        if not (principal_can(p, account, "iam:PassRole")
                and principal_can(p, account, "ec2:RunInstances")):
            continue
        for role_name in targets:
            findings.append(_finding(
                "pass-role-to-new-ec2", "iam:PassRole + ec2:RunInstances", "Critical",
                name, p, target=role_name,
                evidence=f"{name} can launch an EC2 instance with the admin-equivalent instance "
                         f"profile {role_name} and retrieve its credentials from instance metadata.",
            ))
    return findings


def rule_already_admin_equivalent(account):
    findings = []
    for name, p in _all_principals(account):
        if is_admin_equivalent(p, account):
            findings.append(_finding(
                "already-admin-equivalent", "Full admin privileges attached", "Medium",
                name, p, target=name,
                evidence=f"{name} already has an Allow Action:* statement (e.g. AdministratorAccess) "
                         f"-- no escalation needed, they are already an admin.",
            ))
    return findings


ALL_RULES = [
    rule_self_privesc_actions,
    rule_create_or_update_login_profile,
    rule_create_access_key,
    rule_pass_role_to_new_lambda,
    rule_pass_role_to_new_ec2,
    rule_already_admin_equivalent,
]


def run_rules(account: dict) -> list[dict]:
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(account))
    return findings
