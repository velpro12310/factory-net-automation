"""三层与路由测试（6 条，TC-L3-001 ~ 006）。

三层是域间流量的必经之路：所有跨域访问都在核心交换机上完成转发并应用域间 ACL。
这一组验证「路能不能走通」与「走不通时能不能说清为什么」。
"""

from __future__ import annotations

import pytest

from net_auto.faults import apply_mutation
from net_auto.reachability import ReachabilityEngine
from net_auto.traceability import case

pytestmark = pytest.mark.layer3

REQUIRED_STEPS = ["源侧到网关", "网关状态", "域间策略", "目的侧二层"]


@case("TC-L3-001", "REQ-L3-011", priority="P0")
def test_cross_zone_flow_goes_through_core(engine):
    result = engine.check("PLC-01", "MES-APP", "MES-WEB")
    assert result.permitted, f"跨域放通业务流应可达，实际 {result.reason}"
    assert result.layer == "l3", f"跨域流量应判定为三层转发，实际 {result.layer}"

    steps = "\n".join(result.steps)
    for marker in REQUIRED_STEPS:
        assert marker in steps, f"推导步骤缺少「{marker}」：\n{steps}"

    assert result.policy_id == 10, f"应命中策略 10，实际 {result.policy_id}"
    assert "核心交换机" in result.path, f"路径应经核心交换机，实际 {result.path}"


@case("TC-L3-002", "REQ-L3-012", priority="P0")
def test_static_and_default_routes(topology, configs):
    # 核心：缺省路由指向出口路由器
    for core_name, next_hop in [("Core-SW-1", "10.10.88.2"), ("Core-SW-2", "10.10.88.6")]:
        default_routes = [r for r in topology.device(core_name).static_routes
                          if r.dest == "0.0.0.0/0"]
        assert default_routes, f"{core_name} 缺少缺省路由"
        assert default_routes[0].next_hop == next_hop
        assert f"ip route-static 0.0.0.0 0.0.0.0 {next_hop}" in configs[core_name]

    # 接入交换机：管理流量的默认网关指向 VRRP 虚拟地址
    for acc in ("ACC-WORKSHOP", "ACC-OFFICE", "ACC-SERVER"):
        routes = topology.device(acc).static_routes
        assert routes and routes[0].dest == "0.0.0.0/0"
        assert routes[0].next_hop == "10.10.40.254"
        assert "ip route-static 0.0.0.0 0.0.0.0 10.10.40.254" in configs[acc]

    # 出口路由器：回程路由主备 + 公网缺省
    egress = topology.device("RT-EGRESS")
    back = [r for r in egress.static_routes if r.dest == "10.10.0.0/16"]
    assert len(back) == 2, f"回程路由应有主备两条，实际 {len(back)}"
    assert {r.next_hop for r in back} == {"10.10.88.1", "10.10.88.5"}
    assert min(r.metric for r in back) == 10 and max(r.metric for r in back) == 20, (
        "回程路由优先级应为 10（主）/ 20（备）"
    )
    assert any(r.dest == "0.0.0.0/0" and r.next_hop == "198.51.100.1"
               for r in egress.static_routes), "出口路由器缺少公网缺省路由"


@case("TC-L3-003", "REQ-L3-013", priority="P0")
def test_missing_route_makes_zone_unreachable(topology):
    """两台核心都丢掉服务器区 SVI 后，该网段彻底无路由。"""
    mutated = apply_mutation(topology, "remove_svi", {"vlan": 30, "all_cores": True})
    result = ReachabilityEngine(mutated).check("PLC-01", "MES-APP", "MES-WEB")

    assert not result.permitted, "无路由时应不可达"
    assert "无路由" in result.reason or "SVI" in result.reason, (
        f"不可达原因应指向缺少路由/SVI，实际：{result.reason}"
    )

    # 只删一台核心属于配置下发不完整（备份可接管），业务应保持连通
    partial = apply_mutation(topology, "remove_svi", {"vlan": 30, "device": "Core-SW-1"})
    still_ok = ReachabilityEngine(partial).check("PLC-01", "MES-APP", "MES-WEB")
    assert still_ok.permitted, "仅主设备缺 SVI 时备份应接管，业务不应中断"
    assert partial.structural_issues(), "但结构自检必须报出配置不完整"


@case("TC-L3-004", "REQ-L3-014", priority="P0")
def test_cores_have_all_business_svis(topology):
    for core in topology.cores():
        for vlan in (10, 20, 30, 40):
            assert core.svi_for(vlan) is not None, f"{core.name} 缺少 VLAN {vlan} 的 SVI"
            assert core.vrrp_for(vlan) is not None, f"{core.name} 缺少 VLAN {vlan} 的 VRRP 实例"
        # 核心互联与管理口要有地址
        assert core.routed_ports(), f"{core.name} 缺少路由口"
        assert core.has_vlan(99), f"{core.name} 缺少核心互联 VLAN 99"

    # 核心互联地址必须同网段
    a = topology.device("Core-SW-1").iface("GE0/0/20").network
    b = topology.device("Core-SW-2").iface("GE0/0/20").network
    assert a == b, f"核心互联链路两端不在同一网段：{a} vs {b}"


@case("TC-L3-005", "REQ-L3-015", priority="P0")
def test_vrrp_priority_and_preempt(topology, configs):
    for group in topology.vrrp_groups:
        vlan = group["vlan"]
        vrid = group["vrid"]
        master = topology.device(group["master"])
        backup = topology.device(group["backup"])

        assert master.vrrp_for(vlan).priority > backup.vrrp_for(vlan).priority, (
            f"VRRP 组 {vrid}: 主设备优先级应高于备设备"
        )
        assert master.vrrp_for(vlan).priority == group["master_priority"]
        assert backup.vrrp_for(vlan).priority == group["backup_priority"]
        assert master.vrrp_for(vlan).virtual_ip == backup.vrrp_for(vlan).virtual_ip, (
            f"VRRP 组 {vrid}: 主备虚拟地址不一致"
        )

        # 生成配置里必须体现抢占延迟，否则主设备恢复后可能反复抢占引起震荡
        for device in (master, backup):
            text = configs[device.name]
            assert f"vrrp vrid {vrid} virtual-ip {group['virtual_ip']}" in text
            assert f"vrrp vrid {vrid} priority {device.vrrp_for(vlan).priority}" in text
            assert f"vrrp vrid {vrid} preempt-mode timer delay" in text


@case("TC-L3-006", "REQ-MTX-014", priority="P1")
def test_unreachable_conclusions_are_traceable(engine):
    # 被策略拒绝：要给出策略编号与说明
    denied_by_policy = engine.check("PLC-01", "PC-FIN-01", "SMB")
    assert not denied_by_policy.permitted
    assert denied_by_policy.policy_id == 40, (
        f"应命中策略 40（生产网与办公网隔离），实际 {denied_by_policy.policy_id}"
    )
    assert "隔离" in denied_by_policy.reason
    assert denied_by_policy.steps, "拒绝结论必须带推导步骤"

    # 落到默认拒绝：策略编号为 90
    denied_by_default = engine.check("NMS-01", "MES-DB", "MySQL")
    assert not denied_by_default.permitted
    assert denied_by_default.policy_id == 90, (
        f"未显式放通的组合应命中兜底策略 90，实际 {denied_by_default.policy_id}"
    )
    assert "默认拒绝" in denied_by_default.reason

    # 每条拒绝结论的 reason 与 steps 都不得为空
    for result in engine.matrix()[:200]:
        assert result.reason, f"{result.key} 缺少 reason"
        assert result.steps, f"{result.key} 缺少推导步骤"
