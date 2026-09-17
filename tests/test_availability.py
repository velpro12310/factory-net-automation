"""可用性与冗余测试（4 条，TC-AVL-001 ~ 004）。

工厂网停线一次的成本远超冗余设备的采购成本，所以冗余不能只是「配了」，
必须验证「真的起作用」——本组第三条用例就是拿故障注入来证明这一点：
摘掉一条上行链路后，业务可达性必须纹丝不动。
"""

from __future__ import annotations

import pytest

from net_auto.faults import apply_mutation
from net_auto.reachability import ReachabilityEngine, check_expectations, check_invariants
from net_auto.traceability import case

pytestmark = pytest.mark.availability


@case("TC-AVL-001", "REQ-AVL-011", priority="P0")
def test_access_switches_have_dual_uplinks(topology):
    for name in ("ACC-WORKSHOP", "ACC-OFFICE", "ACC-SERVER"):
        device = topology.device(name)
        trunks = device.trunks()
        assert len(trunks) == 2, f"{name} 应有两条上行 Trunk，实际 {len(trunks)}"

        peers = {trunk.peer_device for trunk in trunks}
        assert peers == {"Core-SW-1", "Core-SW-2"}, (
            f"{name} 的两条上行应分别连到两台核心，实际 {peers}"
        )

        for trunk in trunks:
            assert trunk.allow_vlans, f"{name}:{trunk.name} 未放行任何 VLAN"
            # 管理 VLAN 必须放行，否则设备自己失联
            assert 40 in trunk.allow_vlans, f"{name}:{trunk.name} 未放行管理 VLAN 40"


@case("TC-AVL-002", "REQ-AVL-014", priority="P0")
def test_exactly_one_vrrp_gateway_per_vlan(topology):
    for vlan in (10, 20, 30, 40):
        groups = [g for g in topology.vrrp_groups if g["vlan"] == vlan]
        assert len(groups) == 1, f"VLAN {vlan} 应恰好一个 VRRP 组，实际 {len(groups)}"

    # 每个域的网关地址应等于该 VLAN 的 VRRP 虚拟地址
    for zone in topology.zones.values():
        if zone.vlan is None or zone.gateway is None:
            continue
        group = topology.vrrp_for_vlan(zone.vlan)
        assert group is not None, f"安全域 {zone.key} 的 VLAN 没有 VRRP 组"
        assert group["virtual_ip"] == zone.gateway, (
            f"安全域 {zone.key} 的网关 {zone.gateway} 与 VRRP 虚拟地址 "
            f"{group['virtual_ip']} 不一致"
        )

    vips = [g["virtual_ip"] for g in topology.vrrp_groups]
    assert len(vips) == len(set(vips)), f"VRRP 虚拟地址出现重复：{vips}"


@case("TC-AVL-003", "REQ-AVL-013", priority="P0")
def test_single_uplink_failure_keeps_business_alive(topology, expectations):
    """只摘掉一条上行 Trunk 的某个 VLAN（另一条仍放行），业务应不受影响。"""
    mutated = apply_mutation(topology, "remove_vlan_from_trunk_port",
                             {"device": "ACC-SERVER", "port": "GE0/0/24", "vlan": 30})

    engine = ReachabilityEngine(mutated)
    exp_violations = check_expectations(engine, expectations["expectations"])
    inv_violations = check_invariants(engine, expectations["invariants"])

    assert not exp_violations, (
        f"单条链路故障不应影响业务，但有 {len(exp_violations)} 条期望失效，"
        f"例如 {exp_violations[0].id}（{exp_violations[0].reason}）"
    )
    assert not inv_violations, (
        f"单条链路故障不应破坏隔离要求，但有 {len(inv_violations)} 条不变式失效"
    )

    sample = engine.check("PLC-01", "MES-APP", "MES-WEB")
    assert sample.permitted, "备用上行应保证业务继续可达"
    assert "GE0/0/23" in "\n".join(sample.steps) or "Core-SW-2" in "\n".join(sample.steps), (
        "推导应改走另一条上行（Core-SW-2 方向）"
    )

    # 两个上行都摘掉才会真正断
    both = apply_mutation(topology, "remove_vlan_from_all_trunks",
                          {"device": "ACC-SERVER", "vlan": 30})
    assert not ReachabilityEngine(both).check("PLC-01", "MES-APP", "MES-WEB").permitted


@case("TC-AVL-004", "REQ-AVL-011", priority="P1")
def test_egress_router_has_dual_paths(topology):
    egress = topology.device("RT-EGRESS")
    routed = egress.routed_ports()
    peers = {iface.peer_device for iface in routed}
    assert {"Core-SW-1", "Core-SW-2"} <= peers, (
        f"出口路由器应同时连到两台核心，实际对端 {peers}"
    )

    # 两条内网上行应位于不同网段，避免单点失效
    subnets = {iface.network for iface in routed if not iface.is_public
               and iface.peer_device in ("Core-SW-1", "Core-SW-2")}
    assert len(subnets) == 2, f"两条内网上行应在不同网段，实际 {subnets}"

    # 两台核心都应有指向出口的缺省路由，形成双路径
    for core in topology.cores():
        defaults = [r for r in core.static_routes if r.dest == "0.0.0.0/0"]
        assert defaults, f"{core.name} 缺少指向出口的缺省路由"
