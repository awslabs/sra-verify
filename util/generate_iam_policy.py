#!/usr/bin/env python3
"""
Derive the least-privilege member-role IAM policy from the client layer.

Reads every ``services/*/client.py``, works out which boto3 service each
``self.<attr>`` refers to, collects every call made on those attributes, and
emits the action set as JSON and as a CloudFormation managed-policy snippet.

Why this was rewritten
----------------------

The previous implementation matched ``session.client('<service>')`` with regular
expressions. **Nothing in the tree has used that form since the scan-context
refactor** -- every client now acquires its boto3 clients through
``ctx.get_client('<service>', region=...)`` -- so the generator matched nothing and
emitted ``{"Statement": []}``. Its output had therefore been derived from nothing
for some time, which also means "the generated policy is unchanged" was not
evidence of anything.

Attribution, not pattern matching
---------------------------------

The receiver is what identifies the service, and only ``__init__`` knows it.
``WAFClient`` holds nine boto3 clients and ``ShieldClient`` five, so a call like
``self.wafv2_client.get_web_acl_for_resource(...)`` can only be attributed by
first reading ``self.wafv2_client = ctx.get_client('wafv2', ...)``. That is done
here with the AST rather than with regexes, in two passes per module:

1. Bind every ``self.<attr> = ctx.get_client('<service>', ...)`` to its service.
2. Attribute every ``self.<attr>.<method>(...)`` and
   ``self.<attr>.get_paginator('<method>')`` in the module to that service.

The receiver is the *only* source. An earlier draft of the client error contract
had each ``except`` clause name its operation as a string literal, and this module
cross-checked those literals against the receiver methods. That literal is gone --
``AWSClient.aws_error`` reads the operation from ``ClientError.operation_name``,
which botocore sets -- so there is nothing left to cross-check and no second
opinion to reconcile. The AST attribution above is the whole mechanism.

That removed a class of warning, not a class of protection: a literal that
disagreed with the call it labelled was invisible at runtime, which is precisely
why it was dropped in favour of the value botocore already supplies.

Run from the repository root:

    python util/generate_iam_policy.py
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple

import yaml

#: boto3/botocore service id -> IAM action prefix, where the two differ.
#: Everything not listed uses the service id unchanged.
SERVICE_PREFIXES: Dict[str, str] = {
    "accessanalyzer": "access-analyzer",
    "elbv2": "elasticloadbalancing",
    "security-ir": "security-ir",
}

#: boto3 client methods that reach no AWS API.
BOTO3_INTERNAL_METHODS: frozenset[str] = frozenset(
    {
        "get_paginator",
        "get_waiter",
        "can_paginate",
        "generate_presigned_url",
        "generate_presigned_post",
        "close",
        "meta",
    }
)

#: ``s3control`` operations and the ``s3`` action they actually require.
S3CONTROL_TO_S3: Dict[str, str] = {
    "get_public_access_block": "get_account_public_access_block",
}

# Deliberately no acronym normalisation.
#
# A naive snake_case -> PascalCase conversion emits ``GetWebAclForResource`` where
# AWS documents the action as ``GetWebACLForResource``, and ``DescribeDrtAccess``
# where AWS documents ``DescribeDRTAccess``. Normalising those was tried and
# reverted, for two reasons:
#
# 1. IAM evaluates action names case-insensitively, so both spellings authorize
#    the same calls. The difference is cosmetic.
# 2. The committed artefacts and the deployed ``1-sraverify-member-roles.yaml``
#    carry the un-normalised spelling, and the scans they authorize work. Changing
#    the spelling would put a 7-action diff into a deployed IAM policy for no
#    functional gain -- and would destroy the one thing this rewrite is for, which
#    is making "the generated policy is unchanged" mean something again.
#
# If the spelling is ever corrected, it should be its own change, with the
# CloudFormation template updated in the same commit.


def find_client_files(base_dir: str = "./sraverify") -> List[str]:
    """Return every ``client.py`` under ``base_dir``, sorted.

    Args:
        base_dir: Directory to walk.

    Returns:
        Paths, sorted so the output is reproducible.
    """
    found: List[str] = []
    for root, _, files in os.walk(base_dir):
        if "__pycache__" in root:
            continue
        for name in files:
            if name == "client.py":
                found.append(os.path.join(root, name))
    return sorted(found)


def extract_service_name(file_path: str) -> str:
    """Return the service package name from a ``client.py`` path.

    Args:
        file_path: Path of the form ``.../services/<service>/client.py``.

    Returns:
        The service directory name, or ``"unknown"``.
    """
    parts = file_path.split(os.sep)
    for index, part in enumerate(parts):
        if part == "services" and index + 1 < len(parts):
            return parts[index + 1]
    return "unknown"


def _attribute_root(node: ast.AST) -> Tuple[str, ...]:
    """Return an attribute chain as a tuple of names, innermost first.

    Args:
        node: An ``Attribute`` or ``Name`` node.

    Returns:
        e.g. ``("self", "wafv2_client", "get_web_acl_for_resource")``.
    """
    parts: List[str] = []
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return tuple(reversed(parts))


def bind_clients(tree: ast.Module) -> Dict[str, str]:
    """Map ``self.<attr>`` to the boto3 service id it was constructed for.

    Recognizes ``ctx.get_client('<svc>', ...)``, ``self.ctx.get_client(...)``, and
    the legacy ``session.client(...)`` -- the last only so the generator keeps
    working if a module is ever written that way again.

    Args:
        tree: A parsed ``client.py``.

    Returns:
        ``{"wafv2_client": "wafv2", ...}``.
    """
    bindings: Dict[str, str] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue

        service: str | None = None
        for candidate in ast.walk(node.value):
            if not isinstance(candidate, ast.Call):
                continue
            if not isinstance(candidate.func, ast.Attribute):
                continue
            if candidate.func.attr not in {"get_client", "client"}:
                continue
            if candidate.args and isinstance(candidate.args[0], ast.Constant):
                value = candidate.args[0].value
                if isinstance(value, str):
                    service = value
                    break
        if service is None:
            continue

        for target in node.targets:
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "self"
            ):
                bindings[target.attr] = service
            elif isinstance(target, ast.Name):
                # A local, e.g. `sts_client = self.ctx.get_client("sts")`. Still
                # attributed, so a client acquired inside a method body before
                # Requirement 1.11's constructor move is not lost.
                bindings[target.id] = service

    return bindings


def collect_calls(
    tree: ast.Module, bindings: Dict[str, str]
) -> Dict[str, Set[str]]:
    """Attribute every call on a bound receiver to its boto3 service.

    Args:
        tree: A parsed ``client.py``.
        bindings: Output of :func:`bind_clients`.

    Returns:
        ``{"wafv2": {"get_web_acl_for_resource", ...}, ...}``.
    """
    calls: Dict[str, Set[str]] = defaultdict(set)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue

        chain = _attribute_root(node.func)
        if len(chain) < 2:
            continue

        method = chain[-1]
        receiver = chain[-2]
        service = bindings.get(receiver)
        if service is None:
            continue

        if method == "get_paginator":
            if node.args and isinstance(node.args[0], ast.Constant):
                operation = node.args[0].value
                if isinstance(operation, str):
                    calls[service].add(operation)
            continue

        if method in BOTO3_INTERNAL_METHODS:
            continue

        calls[service].add(method)

    return dict(calls)


def generate_iam_policy(service_calls: Dict[str, Set[str]]) -> Dict:
    """Build the policy document from the attributed calls.

    Args:
        service_calls: ``{service_id: {boto3_method, ...}}``. Mutated: the
            ``s3control`` mapping and the dependent-permission additions are
            applied in place, matching the previous behaviour.

    Returns:
        A policy document.
    """
    # s3control's account-level public access block is an s3 action.
    if "s3control" in service_calls:
        service_calls.setdefault("s3", set())
        for call in service_calls["s3control"]:
            service_calls["s3"].add(S3CONTROL_TO_S3.get(call, call))
        service_calls.pop("s3control")

    for calls in service_calls.values():
        calls.discard("get_paginator")

    # Dependent permissions AWS requires alongside the call the client makes.
    if "get_web_acl_for_resource" in service_calls.get("wafv2", set()):
        service_calls["wafv2"].add("get_web_acl")
        service_calls.setdefault("cognito-idp", set()).add("get_web_acl_for_resource")
        service_calls.setdefault("apprunner", set()).add("describe_web_acl_for_service")
        service_calls.setdefault("ec2", set()).add(
            "get_verified_access_instance_web_acl"
        )

    statements: List[Dict] = []
    for service in sorted(service_calls):
        calls = service_calls[service]
        if not calls:
            continue

        if service == "apigateway":
            # API Gateway authorizes by HTTP verb rather than by operation.
            actions = ["apigateway:GET"]
        else:
            prefix = SERVICE_PREFIXES.get(service, service)
            actions = sorted(
                f"{prefix}:{convert_to_api_action(call)}" for call in calls
            )

        statements.append(
            {
                # `str.capitalize()` verbatim, matching the committed artefacts.
                # Note this yields `Cognito-idpPermissions` and
                # `Security-irPermissions`, which are not valid IAM Sids -- a Sid
                # must be alphanumeric. That is pre-existing and harmless here,
                # because `1-sraverify-member-roles.yaml` carries hand-written
                # statements rather than this snippet; the snippet is a reference.
                # Left as-is so this generator reproduces the committed files
                # exactly; fixing it is a separate change.
                "Sid": f"{service.capitalize()}Permissions",
                "Effect": "Allow",
                "Action": actions,
                "Resource": "*",
            }
        )

    return {"Version": "2012-10-17", "Statement": statements}


def convert_to_api_action(method_name: str) -> str:
    """Convert a boto3 method name to its IAM action name.

    Args:
        method_name: e.g. ``"get_web_acl_for_resource"``.

    Returns:
        e.g. ``"GetWebACLForResource"``.
    """
    if "_" in method_name:
        return "".join(part.capitalize() for part in method_name.split("_"))
    return method_name[:1].upper() + method_name[1:]


def build(base_dir: str = "./sraverify") -> Tuple[Dict[str, Set[str]], List[str]]:
    """Attribute every client call in the tree.

    Args:
        base_dir: Directory to walk for ``client.py`` files.

    Returns:
        ``(service_calls, warnings)``.
    """
    service_calls: Dict[str, Set[str]] = defaultdict(set)
    warnings: List[str] = []

    for path in find_client_files(base_dir):
        source = Path(path).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=path)

        bindings = bind_clients(tree)
        calls = collect_calls(tree, bindings)
        for service, methods in calls.items():
            service_calls[service].update(methods)

        if not bindings:
            warnings.append(
                f"{extract_service_name(path)}: no boto3 client binding found; "
                f"every call in this module is unattributed"
            )

    return dict(service_calls), warnings


class NoAliasDumper(yaml.SafeDumper):
    """Emit no aliases, and indent sequences under their key.

    Two deviations from ``SafeDumper``'s defaults, both to reproduce the
    committed ``generated_sraverify_cf_policy.yaml`` byte for byte:

    * **No aliases.** A repeated node would otherwise be emitted as ``&id001`` /
      ``*id001``, which is valid YAML that CloudFormation does not accept.
    * **Indented sequences.** PyYAML writes a block sequence at the same
      indentation as its key by default; the committed file indents it one level,
      which is the conventional CloudFormation style. Without this the generator
      produces a 190-line whitespace-only diff on every run, and a whitespace-only
      diff is indistinguishable from a real one at a glance -- which would undo the
      point of being able to regenerate and compare.
    """

    def ignore_aliases(self, data: object) -> bool:
        """Always ignore aliases.

        Args:
            data: Ignored.

        Returns:
            ``True``.
        """
        return True

    def increase_indent(self, flow: bool = False, indentless: bool = False):
        """Indent block sequences under their parent key.

        Args:
            flow: Whether the collection is in flow style.
            indentless: PyYAML's request to omit the indent; overridden to
                ``False`` for block sequences.

        Returns:
            The result of the base implementation.
        """
        return super().increase_indent(flow, False)


def main() -> int:
    """Attribute the calls, emit the artefacts, and report.

    Returns:
        Process exit status: ``0`` on success, ``1`` if nothing was attributed.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-dir",
        default="./sraverify",
        help="directory to walk for client.py files (default: ./sraverify)",
    )
    parser.add_argument(
        "--out-json",
        default="generated_sraverify_iam_policy.json",
        help="where to write the policy JSON",
    )
    parser.add_argument(
        "--out-yaml",
        default="generated_sraverify_cf_policy.yaml",
        help="where to write the CloudFormation snippet",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="suppress the per-service listing"
    )
    args = parser.parse_args()

    service_calls, warnings = build(args.base_dir)

    if not args.quiet:
        print("=== Boto3 API calls by service (attributed via __init__) ===")
        for service in sorted(service_calls):
            print(f"\n{service}:")
            for call in sorted(service_calls[service]):
                print(f"  - {call}")

    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)

    if not service_calls:
        print(
            "ERROR: no boto3 calls were attributed to any service. The client "
            "layer's client-acquisition form has changed and this generator no "
            "longer recognizes it -- fix that before trusting the output.",
            file=sys.stderr,
        )
        return 1

    policy = generate_iam_policy(service_calls)

    # No trailing newline, matching the committed artefact. A trailing newline
    # would be the better convention, but adding one here would put a permanent
    # one-byte diff into every future regenerate-and-compare -- and the whole
    # point of this rewrite is that such a comparison means something. Fix the
    # newline and the committed file together, or not at all.
    Path(args.out_json).write_text(json.dumps(policy, indent=2), encoding="utf-8")

    cf_policy = {
        "SRAVerifyLeastPrivilege": {
            "Type": "AWS::IAM::ManagedPolicy",
            "Properties": {
                "ManagedPolicyName": "SRAVerifyLeastPrivilege",
                "Description": "Least privilege policy for SRA Verify tool",
                "PolicyDocument": policy,
            },
        }
    }
    Path(args.out_yaml).write_text(
        yaml.dump(
            cf_policy, default_flow_style=False, sort_keys=False, Dumper=NoAliasDumper
        ),
        encoding="utf-8",
    )

    total = sum(len(statement["Action"]) for statement in policy["Statement"])
    print(
        f"\n{len(policy['Statement'])} statements, {total} actions across "
        f"{len(service_calls)} services"
    )
    print(f"Policy written to {args.out_json}")
    print(f"CloudFormation snippet written to {args.out_yaml}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
