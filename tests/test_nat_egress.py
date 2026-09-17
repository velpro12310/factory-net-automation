"""NAT 与出口测试（4 条，TC-NAT-001 ~ 004）。

出网要同时满足两个条件：**策略放通** 且 **NAT 覆盖该源区域**。
只满足一个都不行——这是「加了策略忘了加 NAT 地址池」这类故障的根源。
"""

from __future__ import annotations

import pytest

from net_auto.acl import nat_acl_rules
from net_auto.traceability import case
from net_auto.validator import parse_config

pytestmark = pytest.mark.nat


def flows(engine, from_zone: str, to_zone: str):
    src_hosts = [h for h in engine.topo.hosts.values()
                 if h.zone == from_zone and h.is_internal]
    dst_hosts = [h for h in engine.topo.hosts.values() if h.zone == to_zone]
    return [
        engine.check(src.name, dst.name, svc)
        for src in src_hosts for dst in dst_hosts for svc in engine.topo.services
    ]


@case("TC-NAT-001", "REQ-NAT-011", priority="P0")
def test_office_reaches_internet_via_nat(engine):
    results = flows(engine, "office", "internet")
    assert results, "用例前提不成立：办公区或互联网缺少主机"
    assert all(r.permitted for r in results), (
        f"办公区出网应全放通，实际有 {sum(1 for r in results if not r.permitted)} 条被拒"
    )
    assert all(r.nat_applied for r in results), "出网流量必须标记经 NAT 转换"

    sample = engine.check("PC-FIN-01", "PATCH-SRV", "HTTPS")
    assert sample.policy_id == 50, f"应命中策略 50（办公区经 NAT 访问互联网），实际 {sample.policy_id}"
    assert "NAT" in sample.reason


@case("TC-NAT-002", "REQ-NAT-012", priority="P0")
def test_server_reaches_internet_via_nat(engine):
    results = flows(engine, "server", "internet")
    assert all(r.permitted and r.nat_applied for r in results), (
        "服务器区出网应全放通且经 NAT 转换"
    )

    sample = engine.check("MES-APP", "PATCH-SRV", "HTTPS")
    assert sample.policy_id == 51, f"应命中策略 51（服务器区经 NAT 下载补丁）"
    assert "RT-EGRESS" in sample.path or "RT-EGRESS" in "\n".join(sample.steps), (
        "推导步骤应体现出口路由器"
    )


@case("TC-NAT-003", "REQ-NAT-013", priority="P0")
def test_production_and_mgmt_not_in_nat_scope(engine):
    nat = engine.topo.nat
    assert nat is not None and nat.enabled, "NAT 应处于启用状态"
    assert set(nat.allowed_zones) == {"office", "server"}, (
        f"NAT 允许区域应恰为办公区与服务器区，实际 {nat.allowed_zones}"
    )

    for zone in ("workshop", "mgmt"):
        results = flows(engine, zone, "internet")
        assert all(not r.permitted for r in results), f"{zone} 不应有任何出网通道"

    blocked = engine.check("PLC-01", "PATCH-SRV", "HTTPS")
    assert "NAT" in blocked.reason or "互联网" in blocked.reason, (
        f"出网被拒的原因应能指明方向或 NAT 范围，实际：{blocked.reason}"
    )


@case("TC-NAT-004", "REQ-NAT-014", priority="P1")
def test_nat_acl_and_public_interface_reference(topology, configs):
    nat = topology.nat
    egress_text = configs[nat.device]
    parsed = parse_config(egress_text)

    # ACL 2000 只包含办公区与服务器区网段
    expected = [r.render().strip() for r in nat_acl_rules(topology)]
    assert parsed.acls.get(nat.acl_id) == expected, (
        f"NAT ACL {nat.acl_id} 与规范不一致：\n配置 {parsed.acls.get(nat.acl_id)}\n规范 {expected}"
    )

    # 公网口必须引用该 ACL
    public = parsed.interfaces[f"GigabitEthernet{nat.public_interface[2:]}"]
    assert public.nat_acl == nat.acl_id, "公网口未引用 nat outbound"
    assert public.addr and not public.addr.startswith("10."), (
        "公网口不应使用私网地址"
    )

    # ACL 必须先于 nat outbound 定义，否则命令引用不到 ACL
    acl_pos = egress_text.index(f"acl number {nat.acl_id}")
    nat_pos = egress_text.index(f"nat outbound {nat.acl_id}")
    assert acl_pos < nat_pos, "生成配置中 ACL 定义必须在 nat outbound 之前"
