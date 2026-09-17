"""拓扑数据质量测试（4 条，TC-TOPO-001 ~ 004）。

这一组检查的是**数据本身**，不是网络行为。
把数据错与行为错分开，是排查效率的关键：一个写错的 IP 如果混进配置，
会表现成十几条配置差异，看起来像生成器坏了。
"""

from __future__ import annotations

import ipaddress

import pytest

from net_auto.faults import apply_mutation
from net_auto.traceability import case

pytestmark = pytest.mark.topology


@case("TC-TOPO-001", "REQ-TOPO-011", priority="P0")
def test_links_are_bidirectional(topology):
    assert topology.structural_issues() == [], (
        f"拓扑结构自检应无问题：{topology.structural_issues()}"
    )

    checked = 0
    for device in topology.devices.values():
        for iface in device.interfaces:
            if not iface.peer or iface.peer == "Internet":
                continue
            peer_name, _, peer_port = iface.peer.partition(":")
            if peer_name in topology.hosts:
                host = topology.hosts[peer_name]
                assert host.attached_to == device.name
                assert host.port == iface.name
                checked += 1
                continue
            peer = topology.devices[peer_name]
            back = peer.iface(peer_port)
            assert back is not None, f"{iface.peer} 上不存在该接口"
            assert back.peer == f"{device.name}:{iface.name}", (
                f"连线不对称：{device.name}:{iface.name} -> {iface.peer}，回指 {back.peer}"
            )
            checked += 1
    assert checked >= 20, f"应校验到足够多的链路，实际 {checked}"


@case("TC-TOPO-002", "REQ-TOPO-013", priority="P0")
def test_host_access_ports_are_consistent(topology):
    internal = [h for h in topology.hosts.values() if h.is_internal]
    assert len(internal) == 14, f"内网端系统应为 14 台，实际 {len(internal)}"

    for host in internal:
        device = topology.device(host.attached_to)
        iface = device.iface(host.port)
        assert iface is not None, f"{host.name} 接在 {host.attached_to}:{host.port}，该端口不存在"
        assert iface.type == "access", f"{host.name} 应接在 access 口上，实际 {iface.type}"
        assert iface.vlan == topology.zone(host.zone).vlan, (
            f"{host.name} 属于 {host.zone}（VLAN {topology.zone(host.zone).vlan}），"
            f"但接入口是 VLAN {iface.vlan}"
        )
        assert topology.zone_of_ip(host.ip).key == host.zone, (
            f"{host.name} 的地址 {host.ip} 不在 {host.zone} 的网段内"
        )


@case("TC-TOPO-003", "REQ-TOPO-012", priority="P0")
def test_no_address_conflicts(topology):
    owners: dict[str, list[str]] = {}

    def record(ip: str, owner: str) -> None:
        owners.setdefault(ip, []).append(owner)

    for host in topology.hosts.values():
        if host.is_internal:
            record(host.ip, host.name)
    for device in topology.devices.values():
        record(device.management_ip, f"{device.name}(管理口)")
        for svi in device.svis:
            record(str(svi.interface.ip), f"{device.name}:Vlanif{svi.vlan}")
        for iface in device.routed_ports():
            if iface.ip:
                record(str(ipaddress.ip_interface(iface.ip).ip), f"{device.name}:{iface.name}")
    for group in topology.vrrp_groups:
        record(group["virtual_ip"], f"VRRP-{group['vrid']}")

    # 同一台设备的管理口与其管理 VLAN 的 SVI 是同一地址，属于正常设计
    conflicts = []
    for ip, names in owners.items():
        devices = {n.split(":")[0].split("(")[0] for n in names}
        if len(devices) > 1:
            conflicts.append(f"{ip} 被 {names} 同时占用")
    assert not conflicts, f"存在跨设备地址冲突：{conflicts}"

    # VRRP 虚拟地址不得与任何实体地址重合
    for group in topology.vrrp_groups:
        same = [n for n in owners[group["virtual_ip"]] if not n.startswith("VRRP-")]
        assert not same, f"VRRP 虚拟地址 {group['virtual_ip']} 与实体地址冲突：{same}"


@case("TC-TOPO-004", "REQ-TOPO-014", priority="P1")
def test_undeclared_vlan_is_detected(topology):
    """删除 VLAN 定义后，结构自检必须报错并指出被谁引用。"""
    mutated = apply_mutation(topology, "remove_vlan_definition", {"vlan": 30})
    issues = mutated.structural_issues()
    assert issues, "删除 VLAN 30 后结构自检居然没报错"
    assert any("30" in issue for issue in issues), f"报错信息应指明 VLAN 30：{issues}"

    # 原始拓扑不受影响（注入必须在副本上做）
    assert 30 in topology.vlans, "故障注入污染了原始拓扑"
    assert topology.structural_issues() == []
