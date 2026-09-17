"""二层与 VLAN 测试（6 条，TC-L2-001 ~ 006）。

二层是「隐式」的：配错了不会立刻报错，只是某些主机互相看不见。
本组用例把 VLAN 边界与 Trunk 放行这两件事显式验证出来。
"""

from __future__ import annotations

import pytest

from net_auto.faults import apply_mutation
from net_auto.reachability import ReachabilityEngine
from net_auto.traceability import case

pytestmark = pytest.mark.layer2


@case("TC-L2-001", "REQ-L2-011", priority="P0")
def test_same_switch_same_vlan_is_layer2_direct(engine):
    """PLC-01 与 PLC-02 同接 ACC-WORKSHOP、同属车间 VLAN 10。"""
    result = engine.check("PLC-01", "PLC-02", "NTP")
    assert result.permitted, f"同交换机同 VLAN 应可达，实际 {result.reason}"
    assert result.layer == "l2", f"应判定为二层直达，实际 {result.layer}"
    assert result.policy_id is None, "同域二层流量不应受域间策略约束"
    assert "ACC-WORKSHOP" in result.path


@case("TC-L2-002", "REQ-L2-012", priority="P0")
def test_same_vlan_across_switches_uses_trunk(engine):
    """NMS-01 在 ACC-SERVER、NMS-02 在 ACC-OFFICE，同属管理 VLAN 40。"""
    result = engine.check("NMS-01", "NMS-02", "SSH")
    assert result.permitted, f"同 VLAN 跨交换机应经 Trunk 互通，实际 {result.reason}"
    assert result.layer == "l2", "同 VLAN 跨交换机仍属二层转发"
    assert result.policy_id is None

    iface_a = engine.topo.host("NMS-01").attached_to
    iface_b = engine.topo.host("NMS-02").attached_to
    assert iface_a != iface_b, "本用例前提是两台主机接在不同接入交换机上"
    assert iface_a == "ACC-SERVER" and iface_b == "ACC-OFFICE"

    # 推导步骤里应体现上行 Trunk 的验证
    steps = "\n".join(result.steps)
    assert "Trunk" in steps or "上行" in steps


@case("TC-L2-003", "REQ-L2-013", priority="P0")
def test_cross_vlan_never_layer2_direct(topology, matrix):
    bad = [r for r in matrix if r.is_cross_zone and r.layer == "l2"]
    assert not bad, (
        f"跨 VLAN 不应出现二层直达，实际有 {len(bad)} 条，例如 "
        f"{bad[0].src}->{bad[0].dst}" if bad else ""
    )

    # 每个安全域必须有唯一的 VLAN，否则「域」与「VLAN」不再一一对应
    vlans = [z.vlan for z in topology.zones.values() if z.vlan is not None]
    assert len(vlans) == len(set(vlans)), f"存在多个域共用同一 VLAN：{vlans}"


@case("TC-L2-004", "REQ-L2-014", priority="P0")
def test_trunk_allow_list_governs_vlan_reachability(topology):
    """摘掉服务器区接入交换机全部上行的 VLAN 30 后，该域应立刻不可达。"""
    before = ReachabilityEngine(topology).check("PLC-01", "MES-APP", "MES-WEB")
    assert before.permitted

    mutated = apply_mutation(topology, "remove_vlan_from_all_trunks",
                             {"device": "ACC-SERVER", "vlan": 30})
    after = ReachabilityEngine(mutated).check("PLC-01", "MES-APP", "MES-WEB")

    assert not after.permitted, "摘掉上行 Trunk 的 VLAN 后应不可达"
    assert "二层" in after.reason or "Trunk" in after.reason, (
        f"不可达原因应指向二层/Trunk，实际：{after.reason}"
    )
    # 原始拓扑不受影响
    assert ReachabilityEngine(topology).check("PLC-01", "MES-APP", "MES-WEB").permitted


@case("TC-L2-005", "REQ-L2-014", priority="P1")
def test_trunk_allow_lists_match_on_both_ends(topology):
    mismatched = []
    for device in topology.devices.values():
        for trunk in device.trunks():
            peer_name, _, peer_port = trunk.peer.partition(":")
            peer = topology.devices.get(peer_name)
            if peer is None:
                continue
            back = peer.iface(peer_port)
            if back is None:
                continue
            if sorted(trunk.allow_vlans) != sorted(back.allow_vlans):
                mismatched.append(
                    f"{device.name}:{trunk.name}({sorted(trunk.allow_vlans)}) <-> "
                    f"{peer.name}:{back.name}({sorted(back.allow_vlans)})"
                )
    assert not mismatched, f"以下 Trunk 两端放行列表不一致：{mismatched}"


@case("TC-L2-006", "REQ-L2-015", priority="P1")
def test_access_ports_config_in_generated_files(topology, configs):
    for name, device in topology.devices.items():
        if not device.access_ports():
            continue
        text = configs[name]
        access_count = text.count("port link-type access")
        edged_count = text.count("stp edged-port enable")
        default_vlan_count = text.count("port default vlan ")

        assert access_count == len(device.access_ports()), (
            f"{name} 应有 {len(device.access_ports())} 个 access 口，"
            f"配置里出现 {access_count} 次"
        )
        assert default_vlan_count == access_count, f"{name} 有 access 口未指定默认 VLAN"
        assert edged_count == access_count, (
            f"{name} 的接入端口未全部开启 stp edged-port（接入侧应禁用 STP 参与，避免拓扑震荡）"
        )
        assert "stp bpdu-protection" in text, f"{name} 缺少 BPDU 保护"
