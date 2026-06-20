"""Pulls IAM state from a live AWS account. Read-only: only Get*/List* IAM calls.

Output shape (plain dicts, JSON-serializable -- same shape used by demo/*.json fixtures):

    {
      "account_id": str,
      "users":  {name: {"name", "arn", "type": "user", "policies": [...], "groups": [str]}},
      "roles":  {name: {"name", "arn", "type": "role", "policies": [...], "trust_policy": {...}}},
      "groups": {name: {"name", "policies": [...], "members": [str]}},
    }

`policies` is a list of {"source": "<human label>", "document": {"Statement": [...]}}.
"""
import boto3


def _policy_doc_cache_get(iam, cache, policy_arn):
    if policy_arn not in cache:
        meta = iam.get_policy(PolicyArn=policy_arn)["Policy"]
        version = iam.get_policy_version(
            PolicyArn=policy_arn, VersionId=meta["DefaultVersionId"]
        )["PolicyVersion"]
        cache[policy_arn] = version["Document"]
    return cache[policy_arn]


def _attached_policies(iam, cache, list_fn, **kwargs):
    out = []
    for ap in list_fn(**kwargs)["AttachedPolicies"]:
        doc = _policy_doc_cache_get(iam, cache, ap["PolicyArn"])
        out.append({"source": f"AttachedManagedPolicy:{ap['PolicyName']}", "document": doc})
    return out


def _inline_policies(list_names_fn, get_doc_fn, name_key, **kwargs):
    out = []
    for policy_name in list_names_fn(**kwargs)["PolicyNames"]:
        doc = get_doc_fn(**{**kwargs, name_key: policy_name})["PolicyDocument"]
        out.append({"source": f"InlinePolicy:{policy_name}", "document": doc})
    return out


def collect_account_iam(session: boto3.Session) -> dict:
    iam = session.client("iam")
    policy_cache: dict = {}

    account_id = session.client("sts").get_caller_identity()["Account"]

    groups: dict = {}
    for page in iam.get_paginator("list_groups").paginate():
        for g in page["Groups"]:
            name = g["GroupName"]
            members = [
                u["UserName"]
                for page2 in [iam.get_group(GroupName=name)]
                for u in page2["Users"]
            ]
            policies = _attached_policies(
                iam, policy_cache, iam.list_attached_group_policies, GroupName=name
            ) + _inline_policies(
                iam.list_group_policies, iam.get_group_policy, "PolicyName", GroupName=name
            )
            groups[name] = {"name": name, "policies": policies, "members": members}

    member_of: dict[str, list] = {}
    for gname, g in groups.items():
        for member in g["members"]:
            member_of.setdefault(member, []).append(gname)

    users: dict = {}
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            name = u["UserName"]
            policies = _attached_policies(
                iam, policy_cache, iam.list_attached_user_policies, UserName=name
            ) + _inline_policies(
                iam.list_user_policies, iam.get_user_policy, "PolicyName", UserName=name
            )
            users[name] = {
                "name": name,
                "arn": u["Arn"],
                "type": "user",
                "policies": policies,
                "groups": member_of.get(name, []),
            }

    roles: dict = {}
    for page in iam.get_paginator("list_roles").paginate():
        for r in page["Roles"]:
            name = r["RoleName"]
            policies = _attached_policies(
                iam, policy_cache, iam.list_attached_role_policies, RoleName=name
            ) + _inline_policies(
                iam.list_role_policies, iam.get_role_policy, "PolicyName", RoleName=name
            )
            roles[name] = {
                "name": name,
                "arn": r["Arn"],
                "type": "role",
                "policies": policies,
                "trust_policy": r.get("AssumeRolePolicyDocument", {"Statement": []}),
            }

    return {"account_id": account_id, "users": users, "roles": roles, "groups": groups}
