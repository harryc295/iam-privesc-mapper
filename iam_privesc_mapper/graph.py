"""Builds a principal graph (who can assume what) and finds multi-hop
AssumeRole chains that lead to an admin-equivalent role -- the one
detection that needs traversal rather than a single policy check.
"""
import networkx as nx

from .rules import is_admin_equivalent, principal_can, run_rules


def _trust_allows(principal_arn: str, account_id: str, trust_policy: dict | None) -> bool:
    for stmt in (trust_policy or {}).get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action")
        actions = actions if isinstance(actions, list) else [actions]
        if not any(isinstance(a, str) and a.lower() in ("sts:assumerole", "sts:*", "*") for a in actions):
            continue
        principal_field = stmt.get("Principal")
        if principal_field == "*":
            return True
        aws_principals = principal_field.get("AWS", []) if isinstance(principal_field, dict) else []
        aws_principals = aws_principals if isinstance(aws_principals, list) else [aws_principals]
        if principal_arn in aws_principals or f"arn:aws:iam::{account_id}:root" in aws_principals:
            return True
    return False


def build_graph(account: dict) -> nx.DiGraph:
    g = nx.DiGraph()
    for name, u in account["users"].items():
        g.add_node(name, type="user", admin=is_admin_equivalent(u, account))
    for name, r in account["roles"].items():
        g.add_node(name, type="role", admin=is_admin_equivalent(r, account))

    all_principals = {**account["users"], **account["roles"]}
    for name, p in all_principals.items():
        if not principal_can(p, account, "sts:AssumeRole"):
            continue
        for role_name, role in account["roles"].items():
            if role_name == name:
                continue
            if _trust_allows(p.get("arn", ""), account.get("account_id", ""), role.get("trust_policy")):
                g.add_edge(name, role_name, relation="can_assume")
    return g


def find_assume_role_chains(graph: nx.DiGraph) -> list[dict]:
    findings = []
    admin_roles = {n for n, d in graph.nodes(data=True) if d.get("admin") and d.get("type") == "role"}
    for name, data in graph.nodes(data=True):
        if data.get("admin"):
            continue
        for target in admin_roles:
            if not nx.has_path(graph, name, target):
                continue
            path = nx.shortest_path(graph, name, target)
            hops = len(path) - 1
            findings.append({
                "rule_id": "assume-role-chain-to-admin",
                "title": "sts:AssumeRole chain reaches an admin-equivalent role",
                "severity": "Critical" if hops == 1 else "High",
                "principal": name,
                "principal_type": data["type"],
                "target": target,
                "evidence": f"{' -> '.join(path)}: {name} can reach admin-equivalent role "
                            f"{target} via {hops} AssumeRole hop(s).",
            })
    return findings


def analyze(account: dict) -> tuple[nx.DiGraph, list[dict]]:
    graph = build_graph(account)
    findings = run_rules(account) + find_assume_role_chains(graph)
    return graph, findings
