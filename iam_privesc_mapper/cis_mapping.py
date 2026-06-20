"""Maps findings to compliance controls.

Honest caveat: CIS AWS Foundations Benchmark control numbers shift between
versions (v1.2, v1.4, v1.5, v3.0...) and the benchmark is a baseline-hygiene
checklist, not a privilege-escalation taxonomy -- most of the techniques here
don't have a dedicated CIS control. Only the one mapping we're confident
holds across versions (1.16, full admin policies) is asserted as a specific
control ID. Everything else maps to the general least-privilege control
family (CIS-AWS section 1 / NIST CSF PR.AC-4) with a note explaining why.
Verify against whichever benchmark PDF you cite before using this client-facing.
"""

_LEAST_PRIVILEGE = {
    "cis_aws": ["CIS AWS Foundations section 1 (IAM) -- least-privilege IAM guidance"],
    "nist_csf": ["PR.AC-4 - Access permissions and authorizations are managed, "
                 "incorporating the principles of least privilege"],
    "note": "No single CIS control names this specific technique; it falls under the "
            "benchmark's general least-privilege IAM guidance.",
}

CONTROL_MAP = {
    "already-admin-equivalent": {
        "cis_aws": ["1.16 - Ensure IAM policies that allow full administrative privileges "
                    "are not attached"],
        "nist_csf": ["PR.AC-4"],
        "note": "Direct match -- this rule IS what CIS 1.16 checks for.",
    },
    "iam-create-policy-version": _LEAST_PRIVILEGE,
    "iam-set-default-policy-version": _LEAST_PRIVILEGE,
    "iam-attach-user-policy": _LEAST_PRIVILEGE,
    "iam-attach-role-policy": _LEAST_PRIVILEGE,
    "iam-attach-group-policy": _LEAST_PRIVILEGE,
    "iam-put-user-policy": _LEAST_PRIVILEGE,
    "iam-put-role-policy": _LEAST_PRIVILEGE,
    "iam-put-group-policy": _LEAST_PRIVILEGE,
    "iam-update-assume-role-policy": _LEAST_PRIVILEGE,
    "iam-create-login-profile": _LEAST_PRIVILEGE,
    "iam-update-login-profile": _LEAST_PRIVILEGE,
    "iam-create-access-key": _LEAST_PRIVILEGE,
    "pass-role-to-new-lambda": _LEAST_PRIVILEGE,
    "pass-role-to-new-ec2": _LEAST_PRIVILEGE,
    "assume-role-chain-to-admin": _LEAST_PRIVILEGE,
}


def controls_for(rule_id: str) -> dict:
    return CONTROL_MAP.get(rule_id, _LEAST_PRIVILEGE)
