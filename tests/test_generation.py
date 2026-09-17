"""配置生成与一致性测试（6 条，TC-GEN-001 ~ 006）。

这一组验证「配置即代码」的第一半：拓扑改一处，配置全量重出，且必须与设计意图一致。
六条用例分别打生成、VLAN、接口、网关、ACL、幂等六个面。
"""

from __future__ import annotations

import ipaddress

import pytest

from net_auto.generator import _hw_iface, generate_configs
from net_auto.traceability import case
from net_auto.validator import parse_config

pytestmark = pytest.mark.generation


# --------------------------------------------------------------------------- #
@case("TC-GEN-001", "REQ-GEN-011", priority="P0")
def test_generate_all_configs_with_traceable_header(topology, configs):
    assert set(configs) == set(topology.devices), (
        f"生成结果应与拓扑设备一一对应：缺 {set(topology.devices) - set(configs)}，"
        f"多 {set(configs) - set(topology.devices)}"
    )

    for name, text in configs.items():
        head = "\n".join(text.splitlines()[:12])
        assert f"# {name} —" in head, f"{name} 头部缺少设备名"
        assert "生成时间" in head, f"{name} 头部缺少生成时间"
        assert "拓扑：" in head, f"{name} 头部缺少拓扑版本"
        assert "请勿手工修改" in head, f"{name} 头部缺少禁止手工修改的声明"
        assert "net_auto" in head, f"{name} 头部缺少生成工具标识"

        body = [line for line in text.splitlines() if line and not line.startswith("#")]
        assert body[0] == f"sysname {name}", f"{name} 第一条有效配置不是 sysname"
        assert body[-1] == "return", f"{name} 配置未以 return 结束"


@case("TC-GEN-002", "REQ-GEN-012", priority="P0")
def test_vlan_definitions_complete(topology, configs):
    for name, device in topology.devices.items():
        parsed = parse_config(configs[name])
        assert parsed.sysname == device.name
        if not device.vlans:
            assert "vlan batch" not in configs[name], f"{name} 不该有 vlan batch"
            continue
        missing = sorted(set(device.vlans) - set(parsed.vlans))
        assert not missing, f"{name} 的 vlan batch 缺少 VLAN {missing}"
        assert sorted(parsed.vlans) == sorted(device.vlans), (
            f"{name} 的 vlan batch 多出未声明 VLAN："
            f"{sorted(set(parsed.vlans) - set(device.vlans))}"
        )


@case("TC-GEN-003", "REQ-GEN-013", priority="P0")
def test_interface_config_matches_topology(topology, configs, config_issues):
    for name, device in topology.devices.items():
        parsed = parse_config(configs[name])
        for iface in device.interfaces:
            hw_name = _hw_iface(iface.name)
            got = parsed.interfaces.get(hw_name)
            assert got is not None, f"{name} 缺少接口 {hw_name}"

            if iface.type == "trunk":
                assert got.kind == "trunk", f"{hw_name} 应为 trunk"
                assert sorted(got.allow_vlans) == sorted(iface.allow_vlans), (
                    f"{hw_name} trunk 放行列表不一致"
                )
            elif iface.type == "access":
                assert got.kind == "access", f"{hw_name} 应为 access"
                assert got.vlan == iface.vlan, f"{hw_name} access VLAN 不一致"
            else:
                assert got.kind == "routed", f"{hw_name} 应为路由口"
                expected = ipaddress.ip_interface(iface.ip)
                assert got.addr == f"{expected.ip}/{expected.network.prefixlen}", (
                    f"{hw_name} 地址不一致"
                )

    assert config_issues == {}, f"配置回读比对不应有差异：{config_issues}"


@case("TC-GEN-004", "REQ-GEN-014", priority="P0")
def test_svi_and_vrrp_config_matches_topology(topology, configs):
    for name, device in topology.devices.items():
        parsed = parse_config(configs[name])
        for svi in device.svis:
            hw_name = f"Vlanif{svi.vlan}"
            got = parsed.interfaces.get(hw_name)
            assert got is not None, f"{name} 缺少 {hw_name}"
            expected = ipaddress.ip_interface(svi.ip)
            assert got.addr == f"{expected.ip}/{expected.network.prefixlen}"

        for entry in device.vrrp:
            got = parsed.interfaces[f"Vlanif{entry.vlan}"].vrrp.get(entry.vrid)
            assert got is not None, f"{name} Vlanif{entry.vlan} 缺少 VRID {entry.vrid}"
            assert got["virtual_ip"] == entry.virtual_ip
            assert got["priority"] == entry.priority

    # 核心交换机应把域间 ACL 应用到对应 VLANIF 上
    core = parse_config(configs["Core-SW-1"])
    for vlan, acl in [(10, 3010), (20, 3020), (30, 3030), (40, 3040)]:
        assert core.interfaces[f"Vlanif{vlan}"].acl == acl, (
            f"Core-SW-1 的 Vlanif{vlan} 未引用 ACL {acl}"
        )


@case("TC-GEN-005", "REQ-GEN-016", priority="P0")
def test_acl_matches_policy_table(topology, configs, acls):
    from net_auto.acl import DEFAULT_DENY_POLICY_ID
    from net_auto.validator import RULE_RE

    core_text = configs["Core-SW-1"]
    parsed = parse_config(core_text)

    for zone_key, acl in acls.items():
        actual = parsed.acls.get(acl.acl_number, [])
        expected = [rule.render().strip() for rule in acl.rules]
        assert actual == expected, (
            f"ACL {acl.acl_number}（zone-{zone_key}）与规范规则不一致：\n"
            f"      配置 {actual}\n      规范 {expected}"
        )

    # 策略表必须有 any->any 兜底拒绝，且每个域的 ACL 末条都是拒绝
    assert topology.policies[-1].from_zone == "any"
    assert topology.policies[-1].to_zone == "any"
    assert topology.policies[-1].action == "deny"
    assert topology.policies[-1].id == DEFAULT_DENY_POLICY_ID

    for zone_key, acl in acls.items():
        assert acl.rules[-1].action == "deny", f"{zone_key} 的 ACL 最后一条不是拒绝"

    # 每条规则都能回溯到策略编号（可追溯性）
    for zone_key, acl in acls.items():
        for rule in acl.rules:
            assert rule.policy_id, f"{zone_key} 存在无法回溯策略的规则：{rule.render()}"
            assert RULE_RE.match(rule.render().strip()), "规则渲染格式异常"


@case("TC-GEN-006", "REQ-GEN-017", priority="P1")
def test_generation_is_idempotent(topology):
    first = generate_configs(topology, "固定时间戳")
    second = generate_configs(topology, "固定时间戳")
    assert first == second, "同一拓扑与同一时间戳应生成完全一致的结果"

    other = generate_configs(topology, "另一个时间戳")
    for name in first:
        a = first[name].replace("固定时间戳", "X")
        b = other[name].replace("另一个时间戳", "X")
        assert a == b, f"{name} 除时间戳外出现了其它差异，生成器引入了不确定量"


def test_no_dead_rules_remain_after_canonicalization(acls):
    """ACL 规范化后不应残留死规则（末尾的兜底拒绝除外）。

    这条断言是 CHK-DEADRULE 能力的自检：如果规范化失效，
    生成的 ACL 里会留下永远不会命中的规则，排障时按顺序读会被带偏。
    """
    from net_auto.acl import find_dead_rules

    total_dropped = sum(len(acl.dropped) for acl in acls.values())
    assert total_dropped >= 1, (
        "本拓扑中至少应剔除一条死规则（车间域的 any->mgmt 拒绝被更具体的拒绝覆盖），"
        "剔除数为 0 说明死规则检测失效"
    )

    for zone_key, acl in acls.items():
        body = list(acl.rules[:-1])          # 末条是兜底拒绝，可能被 catch-all 放通遮蔽，豁免
        remaining = find_dead_rules(body)
        assert not remaining, (
            f"{zone_key} 的规范 ACL 中仍残留死规则："
            f"{[r.render().strip() for r in remaining]}"
        )
