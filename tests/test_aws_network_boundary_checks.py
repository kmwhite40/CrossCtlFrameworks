"""Two AWS network-boundary checks, against the highest-weight uncovered practices.

Coverage was 32 checks reaching 18 of the 110 CMMC practices. Of the practices
with no check at all, these four carry five SPRS points each -- the heaviest
weighting the matrix gives -- and are among the first things an assessor asks to
see:

* ``CM.L2-3.4.7``   restrict, disable, or prevent nonessential ports and services
* ``SC.L2-3.13.6``  deny network traffic by default, permit by exception
* ``SC.L2-3.13.1``  monitor, control and protect communications at the boundary
* ``SI.L2-3.14.6``  monitor inbound and outbound traffic to detect attacks

They are also genuinely answerable from an API, which most of the remaining gap
is not: physical protection (3.10.x), personnel screening (3.9.x) and incident
handling (3.6.x) have no provider endpoint that could evidence them, and a check
that pretended otherwise would be worse than the gap.

**Unrestricted ingress is judged per security group**, so a finding names the
group an engineer has to go and fix rather than reporting "the account fails".
**Flow logs are judged per VPC** for the same reason.

The admin-port rule is deliberately narrow: ``0.0.0.0/0`` to SSH or RDP. A
blanket "no unrestricted ingress at all" would fail every public load balancer on
port 443, which is not a finding -- and a check that cries wolf on correct
architecture is how a scanner gets ignored.
"""

from __future__ import annotations

from typing import Any

from ccf.posture.providers import aws

_ACCOUNT = "123456789012"


def _sg(
    group_id: str,
    *,
    permissions: list[dict[str, Any]] | None = None,
    name: str | None = None,
) -> dict[str, Any]:
    return {
        "GroupId": group_id,
        "GroupName": name or group_id,
        "IpPermissions": permissions or [],
    }


def _ingress(
    *, from_port: int, to_port: int, cidrs: list[str], protocol: str = "tcp"
) -> dict[str, Any]:
    return {
        "IpProtocol": protocol,
        "FromPort": from_port,
        "ToPort": to_port,
        "IpRanges": [{"CidrIp": c} for c in cidrs if ":" not in c],
        "Ipv6Ranges": [{"CidrIpv6": c} for c in cidrs if ":" in c],
    }


# ── unrestricted administrative ingress ──────────────────────────────────────


def test_a_group_open_to_the_world_on_ssh_fails() -> None:
    findings = aws.evaluate_security_group_admin_ingress(
        [_sg("sg-bad", permissions=[_ingress(from_port=22, to_port=22, cidrs=["0.0.0.0/0"])])],
        account_id=_ACCOUNT,
    )
    assert [f.verdict for f in findings] == ["fail"]
    assert findings[0].resource_id == "sg-bad"
    assert findings[0].resource_type == "aws_security_group"
    assert "22" in findings[0].observed


def test_a_group_open_to_the_world_on_rdp_fails() -> None:
    findings = aws.evaluate_security_group_admin_ingress(
        [_sg("sg-rdp", permissions=[_ingress(from_port=3389, to_port=3389, cidrs=["0.0.0.0/0"])])],
        account_id=_ACCOUNT,
    )
    assert [f.verdict for f in findings] == ["fail"]
    assert "3389" in findings[0].observed


def test_ipv6_any_address_is_unrestricted_too() -> None:
    """``::/0`` is the same exposure as ``0.0.0.0/0`` and is easy to forget."""
    findings = aws.evaluate_security_group_admin_ingress(
        [_sg("sg-v6", permissions=[_ingress(from_port=22, to_port=22, cidrs=["::/0"])])],
        account_id=_ACCOUNT,
    )
    assert [f.verdict for f in findings] == ["fail"]
    assert "::/0" in findings[0].observed


def test_an_admin_port_inside_a_range_is_caught() -> None:
    """A rule opening 1-65535 exposes SSH without naming it.

    The likeliest real-world shape, and the one a port-equality check misses.
    """
    findings = aws.evaluate_security_group_admin_ingress(
        [_sg("sg-all", permissions=[_ingress(from_port=1, to_port=65535, cidrs=["0.0.0.0/0"])])],
        account_id=_ACCOUNT,
    )
    assert [f.verdict for f in findings] == ["fail"]


def test_all_protocols_with_no_ports_is_caught() -> None:
    """``IpProtocol: -1`` means every protocol and port, and carries no FromPort."""
    findings = aws.evaluate_security_group_admin_ingress(
        [
            {
                "GroupId": "sg-any",
                "GroupName": "any",
                "IpPermissions": [
                    {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ],
            }
        ],
        account_id=_ACCOUNT,
    )
    assert [f.verdict for f in findings] == ["fail"]


def test_a_public_web_port_is_not_a_finding() -> None:
    """443 open to the world is ordinary architecture, not a weakness.

    The check that fails this is the check an operator learns to ignore.
    """
    findings = aws.evaluate_security_group_admin_ingress(
        [_sg("sg-web", permissions=[_ingress(from_port=443, to_port=443, cidrs=["0.0.0.0/0"])])],
        account_id=_ACCOUNT,
    )
    assert [f.verdict for f in findings] == ["pass"]


def test_ssh_from_a_corporate_range_is_not_a_finding() -> None:
    """The requirement is permit-by-exception, and this is the exception."""
    findings = aws.evaluate_security_group_admin_ingress(
        [_sg("sg-corp", permissions=[_ingress(from_port=22, to_port=22, cidrs=["10.0.0.0/8"])])],
        account_id=_ACCOUNT,
    )
    assert [f.verdict for f in findings] == ["pass"]


def test_each_group_is_judged_on_its_own() -> None:
    """One bad group must not condemn the others, nor they excuse it."""
    findings = aws.evaluate_security_group_admin_ingress(
        [
            _sg("sg-ok", permissions=[_ingress(from_port=443, to_port=443, cidrs=["0.0.0.0/0"])]),
            _sg("sg-bad", permissions=[_ingress(from_port=22, to_port=22, cidrs=["0.0.0.0/0"])]),
            _sg("sg-empty"),
        ],
        account_id=_ACCOUNT,
    )
    by_id = {f.resource_id: f.verdict for f in findings}
    assert by_id == {"sg-ok": "pass", "sg-bad": "fail", "sg-empty": "pass"}


def test_no_groups_is_unassessable_not_a_pass() -> None:
    """An account that reported no security groups has not been shown compliant.

    Every AWS account has at least a default group, so an empty answer means the
    call did not answer -- reporting that as ``pass`` is the overclaim this
    codebase keeps finding elsewhere.
    """
    findings = aws.evaluate_security_group_admin_ingress([], account_id=_ACCOUNT)
    assert [f.verdict for f in findings] == ["manual_review_required"]
    assert findings[0].resource_id == _ACCOUNT


# ── VPC flow logs ────────────────────────────────────────────────────────────


def _vpc(vpc_id: str, *, flow_logs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {"VpcId": vpc_id, "FlowLogs": flow_logs or []}


def test_a_vpc_with_an_active_flow_log_passes() -> None:
    findings = aws.evaluate_vpc_flow_logs(
        [_vpc("vpc-1", flow_logs=[{"FlowLogId": "fl-1", "FlowLogStatus": "ACTIVE"}])],
        account_id=_ACCOUNT,
    )
    assert [f.verdict for f in findings] == ["pass"]
    assert findings[0].resource_id == "vpc-1"
    assert findings[0].resource_type == "aws_vpc"


def test_a_vpc_with_no_flow_log_fails() -> None:
    findings = aws.evaluate_vpc_flow_logs([_vpc("vpc-dark")], account_id=_ACCOUNT)
    assert [f.verdict for f in findings] == ["fail"]
    assert "no flow log" in findings[0].observed.lower()


def test_a_flow_log_that_is_not_active_does_not_count() -> None:
    """A log in ``FAILED`` delivers nothing, so the boundary is unmonitored.

    Reading the row's presence rather than its status is the easy mistake, and it
    reports a blind VPC as monitored.
    """
    findings = aws.evaluate_vpc_flow_logs(
        [_vpc("vpc-broken", flow_logs=[{"FlowLogId": "fl-x", "FlowLogStatus": "FAILED"}])],
        account_id=_ACCOUNT,
    )
    assert [f.verdict for f in findings] == ["fail"]
    assert "FAILED" in findings[0].observed


def test_each_vpc_is_judged_on_its_own() -> None:
    findings = aws.evaluate_vpc_flow_logs(
        [
            _vpc("vpc-ok", flow_logs=[{"FlowLogId": "fl-1", "FlowLogStatus": "ACTIVE"}]),
            _vpc("vpc-dark"),
        ],
        account_id=_ACCOUNT,
    )
    assert {f.resource_id: f.verdict for f in findings} == {"vpc-ok": "pass", "vpc-dark": "fail"}


def test_no_vpcs_is_unassessable_not_a_pass() -> None:
    findings = aws.evaluate_vpc_flow_logs([], account_id=_ACCOUNT)
    assert [f.verdict for f in findings] == ["manual_review_required"]


# ── registration ─────────────────────────────────────────────────────────────


def test_both_checks_are_registered_with_their_permissions() -> None:
    """A check nobody can read is a check that reports manual_review forever."""
    for check, permission in (
        (aws.SECURITY_GROUP_ADMIN_INGRESS, "ec2:DescribeSecurityGroups"),
        (aws.VPC_FLOW_LOGS, "ec2:DescribeFlowLogs"),
    ):
        assert check.provider == "aws_govcloud"
        assert permission in check.required_permissions
        assert check.control_ids, "a check must declare what it evidences"
        assert check.expected, "a verdict is only explainable beside its expectation"
