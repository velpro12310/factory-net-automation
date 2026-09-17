"""安全策略与 ACL 测试（8 条，TC-ACL-001 ~ 008）。

工厂网的安全策略有三个硬要求，本组用例逐一验证：
  1. 生产网与办公网**完全**隔离（不是「大部分隔离」）
  2. 生产网没有任何出网通道（合规要求）
  3. 未显式放通的一律拒绝（默认拒绝，而不是默认放通）

前两条必须用「全主机 × 全服务」的方式验证——只挑几条流试，
很容易漏掉某个主机或某个协议上的口子。
"""

from __future__ import annotations

from typing import List

import pytest

from net_auto.traceability import case

pytestmark = pytest.mark.security

WORKSHOP_PERMITTED = ["MES-WEB", "MySQL", "OPC-UA", "NTP", "ICMP"]
WORKSHOP_DENIED = ["HTTP", "HTTPS", "SMB", "SSH", "SNMP"]
OFFICE_PERMITTED = ["HTTP", "HTTPS", "MES-WEB"]
OFFICE_DENIED = ["MySQL", "OPC-UA", "SMB", "SSH", "SNMP", "NTP", "ICMP"]
MGMT_PERMITTED = ["SSH", "SNMP", "ICMP"]
MGMT_DENIED = ["MES-WEB", "MySQL", "OPC-UA", "HTTP", "HTTPS", "SMB", "NTP"]


def flows(engine, from_zone: str, to_zone: str, services: List[str]):
    src_hosts = [h for h in engine.topo.hosts.values()
                 if h.zone == from_zone and h.is_internal]
    dst_hosts = [h for h in engine.topo.hosts.values() if h.zone == to_zone]
    assert src_hosts and dst_hosts, f"域 {from_zone}->{to_zone} 缺少主机，用例前提不成立"
    return [
        engine.check(src.name, dst.name, svc)
        for src in src_hosts for dst in dst_hosts for svc in services
    ]


def assert_all(results, expect_permit: bool, label: str) -> None:
    wrong = [r for r in results if r.permitted != expect_permit]
    assert not wrong, (
        f"{label}：{len(wrong)}/{len(results)} 条不符预期（"
        f"期望{'放通' if expect_permit else '阻断'}），"
        f"例如 {wrong[0].src}->{wrong[0].dst}:{wrong[0].service} = "
        f"{wrong[0].verdict}（{wrong[0].reason}）"
    )


# --------------------------------------------------------------------------- #
@case("TC-ACL-001", "REQ-ACL-011", priority="P0")
def test_workshop_to_server_by_whitelist(engine):
    assert_all(flows(engine, "workshop", "server", WORKSHOP_PERMITTED), True,
               "车间到服务器区的白名单端口应全部放通")
    assert_all(flows(engine, "workshop", "server", WORKSHOP_DENIED), False,
               "车间到服务器区未放通端口应全部阻断")

    # 抽查一条，确认走的是三层且命中策略 10
    sample = engine.check("PLC-01", "MES-APP", "MES-WEB")
    assert sample.policy_id == 10 and sample.layer == "l3"


@case("TC-ACL-002", "REQ-ACL-012", priority="P0")
def test_office_to_server_only_web(engine):
    assert_all(flows(engine, "office", "server", OFFICE_PERMITTED), True,
               "办公区到服务器区的 Web 端口应放通")
    assert_all(flows(engine, "office", "server", OFFICE_DENIED), False,
               "办公区到服务器区未放通服务应阻断（含数据库 3306）")

    db = engine.check("PC-FIN-01", "MES-DB", "MySQL")
    assert not db.permitted and db.policy_id == 44, (
        f"数据库访问应由策略 44 拒绝，实际 policy_id={db.policy_id}"
    )


@case("TC-ACL-003", "REQ-ACL-013", priority="P0")
def test_workshop_and_office_fully_isolated(engine):
    all_services = list(engine.topo.services)
    forward = flows(engine, "workshop", "office", all_services)
    backward = flows(engine, "office", "workshop", all_services)

    assert_all(forward, False, "车间到办公区应全阻断")
    assert_all(backward, False, "办公区到车间应全阻断")

    # 隔离必须双向成立，不能只做单向 ACL
    assert len(forward) == len(backward), "双向用例数量应一致"

    # 生产网到办公网必须先于出网放通规则被拒绝
    sample = engine.check("PLC-01", "PC-PLN-01", "HTTP")
    assert sample.policy_id == 40


@case("TC-ACL-004", "REQ-ACL-014", priority="P0")
def test_server_cannot_initiate_to_production(engine):
    all_services = list(engine.topo.services)
    assert_all(flows(engine, "server", "workshop", all_services), False,
               "服务器区到车间应全阻断")
    assert_all(flows(engine, "server", "office", all_services), False,
               "服务器区到办公区应全阻断")

    sample = engine.check("MES-APP", "PLC-01", "MES-WEB")
    assert sample.policy_id == 42, "应由策略 42（服务器区不得主动访问生产设备）拒绝"


@case("TC-ACL-005", "REQ-ACL-015", priority="P0")
def test_workshop_has_no_internet_path(engine):
    assert_all(flows(engine, "workshop", "internet", list(engine.topo.services)), False,
               "车间到互联网应全阻断")

    nat = engine.topo.nat
    assert "workshop" not in nat.allowed_zones, "车间不得出现在 NAT 允许区域中"
    assert "mgmt" not in nat.allowed_zones, "管理区不得出现在 NAT 允许区域中"

    sample = engine.check("PLC-01", "PATCH-SRV", "HTTPS")
    assert sample.policy_id == 45, "应由策略 45（生产网禁止访问互联网）拒绝"


@case("TC-ACL-006", "REQ-ACL-016", priority="P0")
def test_mgmt_can_manage_all_devices(engine):
    internal_zones = ["workshop", "office", "server"]
    for zone in internal_zones:
        assert_all(flows(engine, "mgmt", zone, MGMT_PERMITTED), True,
                   f"管理区到 {zone} 的 SSH/SNMP/ICMP 应放通")
        assert_all(flows(engine, "mgmt", zone, MGMT_DENIED), False,
                   f"管理区到 {zone} 的其它服务应阻断")

    # SNMP 走 UDP，必须单独验证：把 161 写在 TCP 规则里是个常见错误
    snmp = engine.check("NMS-01", "ROBOT-01", "SNMP")
    assert snmp.permitted, "SNMP(udp/161) 应放通——检查策略是否把 161 误写成 TCP"
    assert snmp.policy_id == 32


@case("TC-ACL-007", "REQ-ACL-017", priority="P0")
def test_only_mgmt_can_enter_management_zone(engine):
    for zone in ("workshop", "office", "server"):
        assert_all(flows(engine, zone, "mgmt", list(engine.topo.services)), False,
                   f"{zone} 到管理区应全阻断")

    # 方向不可逆：管理区到生产设备是通的，反向不通
    forward = engine.check("NMS-01", "PLC-01", "SSH")
    backward = engine.check("PLC-01", "NMS-01", "SSH")
    assert forward.permitted and not backward.permitted, (
        "管理方向必须单向：管理区→设备 通，设备→管理区 不通"
    )


@case("TC-ACL-008", "REQ-ACL-018", priority="P0")
def test_unlisted_combinations_fall_to_default_deny(engine):
    """既没有放通规则、也没有更具体的拒绝规则命中的组合，必须落到兜底默认拒绝。"""
    fallthrough = [
        ("NMS-01", "MES-DB", "MySQL"),      # 管理区不必访问数据库
        ("NMS-01", "NTP-SRV", "NTP"),       # 时间同步不在管理区放通列表内
        ("NMS-02", "PLC-01", "HTTP"),       # 管理区到生产设备的 Web 未声明
    ]
    for src, dst, svc in fallthrough:
        result = engine.check(src, dst, svc)
        assert not result.permitted, f"{src}->{dst}:{svc} 应被默认拒绝"
        assert result.policy_id == 90, (
            f"{src}->{dst}:{svc} 应命中兜底策略 90，实际 {result.policy_id}"
            f"（{result.reason}）"
        )
        assert "默认拒绝" in result.reason

    # 对比：被更具体的拒绝规则拦下时，应给出那条规则的编号而不是兜底 90
    specific = engine.check("PRINTER-01", "MES-APP", "SMB")
    assert not specific.permitted
    assert specific.policy_id == 44, (
        f"办公区到服务器区的未放通服务应由策略 44 拒绝，实际 {specific.policy_id}"
        f"——错误码指向具体规则比指向兜底更有诊断价值"
    )

    # 策略表最后一条必须是 any->any 拒绝
    assert engine.topo.policies[-1].from_zone == "any"
    assert engine.topo.policies[-1].to_zone == "any"
    assert engine.topo.policies[-1].action == "deny"
