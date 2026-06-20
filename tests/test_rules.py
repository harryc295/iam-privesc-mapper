"""Run with: python -m pytest
(uses -m so the repo root, and therefore iam_privesc_mapper/, is on sys.path)
"""
from iam_privesc_mapper.graph import build_graph, find_assume_role_chains
from iam_privesc_mapper.rules import (
    is_admin_equivalent,
    principal_can,
    rule_create_access_key,
    rule_pass_role_to_new_lambda,
    run_rules,
)


def _account(users=None, roles=None, groups=None, account_id="123456789012"):
    return {"account_id": account_id, "users": users or {}, "roles": roles or {}, "groups": groups or {}}


def _principal(name, statements, type_="user", groups=None, trust_policy=None):
    p = {
        "name": name,
        "arn": f"arn:aws:iam::123456789012:{type_}/{name}",
        "type": type_,
        "policies": [{"source": "test", "document": {"Statement": statements}}],
        "groups": groups or [],
    }
    if type_ == "role":
        p["trust_policy"] = trust_policy or {"Statement": []}
    return p


def test_direct_self_privesc_action_is_flagged():
    alice = _principal("alice", [{"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"}])
    account = _account(users={"alice": alice})
    rule_ids = {f["rule_id"] for f in run_rules(account)}
    assert "iam-attach-user-policy" in rule_ids


def test_scoped_policy_is_not_flagged():
    bob = _principal("bob", [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}])
    account = _account(users={"bob": bob})
    assert run_rules(account) == []


def test_explicit_deny_overrides_allow():
    eve = _principal("eve", [
        {"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"},
        {"Effect": "Deny", "Action": "iam:AttachUserPolicy", "Resource": "*"},
    ])
    account = _account(users={"eve": eve})
    assert principal_can(eve, account, "iam:AttachUserPolicy") is False


def test_permission_inherited_from_group():
    dev_group = {
        "name": "developers",
        "policies": [{"source": "test", "document": {"Statement": [
            {"Effect": "Allow", "Action": "iam:PutUserPolicy", "Resource": "*"}
        ]}}],
        "members": ["dana"],
    }
    dana = _principal("dana", statements=[], groups=["developers"])
    account = _account(users={"dana": dana}, groups={"developers": dev_group})
    assert principal_can(dana, account, "iam:PutUserPolicy") is True


def test_create_access_key_targets_other_users_not_self():
    mallory = _principal("mallory", [{"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"}])
    victim = _principal("victim", [])
    account = _account(users={"mallory": mallory, "victim": victim})
    findings = rule_create_access_key(account)
    targets = {f["target"] for f in findings}
    assert targets == {"victim"}


def test_pass_role_requires_all_three_lambda_actions():
    half_privs = _principal("half", [
        {"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction"], "Resource": "*"},
    ])
    admin_role = _principal("AdminRole", [{"Effect": "Allow", "Action": "*", "Resource": "*"}], type_="role")
    account = _account(users={"half": half_privs}, roles={"AdminRole": admin_role})
    assert rule_pass_role_to_new_lambda(account) == []

    full_privs = _principal("full", [
        {"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"},
    ])
    account["users"]["full"] = full_privs
    findings = rule_pass_role_to_new_lambda(account)
    assert any(f["principal"] == "full" and f["target"] == "AdminRole" for f in findings)


def test_admin_equivalent_detection():
    admin = _principal("AdminRole", [{"Effect": "Allow", "Action": "*", "Resource": "*"}], type_="role")
    scoped = _principal("ScopedRole", [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}], type_="role")
    account = _account(roles={"AdminRole": admin, "ScopedRole": scoped})
    assert is_admin_equivalent(admin, account) is True
    assert is_admin_equivalent(scoped, account) is False


def test_assume_role_chain_to_admin_is_found():
    admin_role = _principal(
        "AdminRole", [{"Effect": "Allow", "Action": "*", "Resource": "*"}], type_="role",
        trust_policy={"Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:user/charlie"},
             "Action": "sts:AssumeRole"}
        ]},
    )
    charlie = _principal("charlie", [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}])
    account = _account(users={"charlie": charlie}, roles={"AdminRole": admin_role})

    graph = build_graph(account)
    findings = find_assume_role_chains(graph)
    assert any(f["principal"] == "charlie" and f["target"] == "AdminRole" for f in findings)


def test_no_chain_when_trust_policy_does_not_name_principal():
    admin_role = _principal(
        "AdminRole", [{"Effect": "Allow", "Action": "*", "Resource": "*"}], type_="role",
        trust_policy={"Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:user/someone-else"},
             "Action": "sts:AssumeRole"}
        ]},
    )
    charlie = _principal("charlie", [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}])
    account = _account(users={"charlie": charlie}, roles={"AdminRole": admin_role})

    graph = build_graph(account)
    findings = find_assume_role_chains(graph)
    assert findings == []
