"""生成配置的一致性校验：把生成的配置**解析回结构**，与拓扑模型逐条比对。

为什么必须有这一步：
生成器完全可能「模板写错了但生成不报错」——比如 trunk 口漏放一个 VLAN、
ACL 顺序被模板搞乱、某台设备少下了一条路由。人眼审几十台设备的配置必然漏，
所以要把配置反向解析回模型，用机器比对。

这也是「配置即代码」闭环的最后一环：

    拓扑 YAML  --生成-->  设备配置  --解析-->  结构化数据  --比对-->  拓扑 YAML
         ^                                                              |
         +----------------------- 不一致即报错 --------------------------+

闭环闭合后，「设备上配的」与「文档里写的」就再也不会漂移。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .acl import all_canonical_acls, nat_acl_rules
from .model import Device, Topology
from .generator import _hw_iface  # noqa: PLC2701  同一包内的渲染辅助函数

# --------------------------------------------------------------------------- #
ROUTE_RE = re.compile(
    r"^ip route-static\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+preference\s+(\d+))?$"
)
RULE_RE = re.compile(r"^rule\s+(\d+)\s+(permit|deny)\s+(.*)$")
VRRP_VIP_RE = re.compile(r"^vrrp vrid (\d+) virtual-ip (\S+)$")
VRRP_PRI_RE = re.compile(r"^vrrp vrid (\d+) priority (\d+)$")


@dataclass
class ParsedInterface:
    name: str
    kind: str = "unknown"                 # trunk | access | routed
    vlan: Optional[int] = None
    allow_vlans: Tuple[int, ...] = ()
    addr: Optional[str] = None
    acl: Optional[int] = None
    vrrp: Dict[int, Dict[str, object]] = field(default_factory=dict)
    nat_acl: Optional[int] = None


@dataclass
class ParsedConfig:
    sysname: str = ""
    vlans: Tuple[int, ...] = ()
    interfaces: Dict[str, ParsedInterface] = field(default_factory=dict)
    routes: List[Tuple[str, str, str, int]] = field(default_factory=list)
    acls: Dict[int, List[str]] = field(default_factory=dict)
    has_ntp: bool = False
    has_loghost: bool = False


def parse_config(text: str) -> ParsedConfig:
    """解析生成的 VRP 配置。只解析本工程模板会产出的语法子集。"""
    parsed = ParsedConfig()
    current_iface: Optional[ParsedInterface] = None
    current_acl: Optional[int] = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue

        if line.startswith("#"):
            # 段分隔注释（# ---- xxx ----）表示上一段结束。
            # 必须在这里重置上下文，否则「最后一个接口」的上下文会一直生效，
            # 把后面的 ip route-static 行当成接口子命令吞掉——
            # 本工程的接入交换机模板就踩了这个坑（路由段注释带了括号后缀，
            # 早期用的精确匹配没命中，导致三条静态路由全部解析不到）。
            if line.startswith("# ----"):
                current_iface = None
                current_acl = None
            continue

        stripped = line.strip()

        if stripped.startswith("sysname "):
            parsed.sysname = stripped.split(None, 1)[1]
            continue
        if stripped.startswith("vlan batch "):
            parsed.vlans = tuple(int(v) for v in stripped.split()[2:])
            continue
        if stripped.startswith("ntp-service unicast-server"):
            parsed.has_ntp = True
            continue
        if stripped.startswith("info-center loghost"):
            parsed.has_loghost = True
            continue

        if stripped.startswith("interface "):
            name = stripped.split(None, 1)[1]
            current_iface = ParsedInterface(name=name)
            parsed.interfaces[name] = current_iface
            current_acl = None
            continue

        if stripped.startswith("acl number "):
            current_acl = int(stripped.split()[2])
            parsed.acls[current_acl] = []
            current_iface = None
            continue

        if current_acl is not None:
            if RULE_RE.match(stripped):
                parsed.acls[current_acl].append(stripped)
            continue

        if current_iface is not None:
            if stripped == "port link-type trunk":
                current_iface.kind = "trunk"
            elif stripped == "port link-type access":
                current_iface.kind = "access"
            elif stripped == "undo portswitch":
                current_iface.kind = "routed"
            elif stripped.startswith("port trunk allow-pass vlan "):
                current_iface.allow_vlans = tuple(
                    int(v) for v in stripped.split()[4:]
                )
            elif stripped.startswith("port default vlan "):
                current_iface.vlan = int(stripped.split()[3])
            elif stripped.startswith("ip address "):
                parts = stripped.split()
                current_iface.addr = f"{parts[2]}/{ipaddress.ip_network(f'0.0.0.0/{parts[3]}').prefixlen}"
            elif stripped.startswith("traffic-filter inbound acl "):
                current_iface.acl = int(stripped.split()[-1])
            elif stripped.startswith("nat outbound "):
                current_iface.nat_acl = int(stripped.split()[-1])
            else:
                vip = VRRP_VIP_RE.match(stripped)
                pri = VRRP_PRI_RE.match(stripped)
                if vip:
                    vrid = int(vip.group(1))
                    current_iface.vrrp.setdefault(vrid, {})["virtual_ip"] = vip.group(2)
                elif pri:
                    vrid = int(pri.group(1))
                    current_iface.vrrp.setdefault(vrid, {})["priority"] = int(pri.group(2))
            continue

        route = ROUTE_RE.match(stripped)
        if route:
            net, mask, nh, pref = route.groups()
            prefix = ipaddress.ip_network(f"{net}/{mask}", strict=False).prefixlen
            parsed.routes.append((f"{net}/{prefix}", nh, mask, int(pref or 60)))

    return parsed


# --------------------------------------------------------------------------- #
def check_config(topology: Topology, device: Device, text: str) -> List[str]:
    """把一份生成的配置与拓扑模型比对，返回不一致项。"""
    issues: List[str] = []
    parsed = parse_config(text)

    # 1) 设备名
    if parsed.sysname != device.name:
        issues.append(f"sysname 不一致：配置为 {parsed.sysname!r}，模型为 {device.name!r}")

    # 2) VLAN 定义
    missing_vlans = sorted(set(device.vlans) - set(parsed.vlans))
    if missing_vlans:
        issues.append(f"vlan batch 缺少 VLAN：{missing_vlans}")

    # 3) 接口
    for iface in device.interfaces:
        hw_name = _hw_iface(iface.name)
        got = parsed.interfaces.get(hw_name)
        if got is None:
            issues.append(f"配置里缺少接口 {hw_name}")
            continue
        if got.kind != iface.type:
            issues.append(
                f"{hw_name} 接口类型不一致：配置 {got.kind}，模型 {iface.type}"
            )
        if iface.type == "trunk":
            if tuple(sorted(got.allow_vlans)) != tuple(sorted(iface.allow_vlans)):
                issues.append(
                    f"{hw_name} trunk 放行 VLAN 不一致："
                    f"配置 {sorted(got.allow_vlans)}，模型 {sorted(iface.allow_vlans)}"
                )
        elif iface.type == "access":
            if got.vlan != iface.vlan:
                issues.append(
                    f"{hw_name} access VLAN 不一致：配置 {got.vlan}，模型 {iface.vlan}"
                )
        elif iface.type == "routed" and iface.ip:
            expected = ipaddress.ip_interface(iface.ip)
            if got.addr != f"{expected.ip}/{expected.network.prefixlen}":
                issues.append(
                    f"{hw_name} 地址不一致：配置 {got.addr}，模型 {iface.ip}"
                )

    # 4) SVI
    for svi in device.svis:
        hw_name = f"Vlanif{svi.vlan}"
        got = parsed.interfaces.get(hw_name)
        if got is None:
            issues.append(f"配置里缺少 {hw_name}")
            continue
        expected = ipaddress.ip_interface(svi.ip)
        if got.addr != f"{expected.ip}/{expected.network.prefixlen}":
            issues.append(f"{hw_name} 地址不一致：配置 {got.addr}，模型 {svi.ip}")
        for entry in device.vrrp:
            if entry.vlan != svi.vlan:
                continue
            got_vrrp = got.vrrp.get(entry.vrid)
            if got_vrrp is None:
                issues.append(f"{hw_name} 缺少 VRID {entry.vrid} 的 VRRP 配置")
                continue
            if got_vrrp.get("virtual_ip") != entry.virtual_ip:
                issues.append(
                    f"{hw_name} VRRP 虚拟地址不一致："
                    f"配置 {got_vrrp.get('virtual_ip')}，模型 {entry.virtual_ip}"
                )
            if got_vrrp.get("priority") != entry.priority:
                issues.append(
                    f"{hw_name} VRRP 优先级不一致："
                    f"配置 {got_vrrp.get('priority')}，模型 {entry.priority}"
                )

    # 5) 静态路由
    expected_routes = []
    for route in device.static_routes:
        net = ipaddress.ip_network(route.dest, strict=False)
        expected_routes.append((f"{net.network_address}/{net.prefixlen}",
                                route.next_hop, str(net.netmask), route.metric))
    if sorted(expected_routes) != sorted(parsed.routes):
        issues.append(
            f"静态路由不一致：\n      配置 {sorted(parsed.routes)}\n"
            f"      模型 {sorted(expected_routes)}"
        )

    # 6) ACL：核心交换机上才下发
    if device.role == "core":
        for zone_key, acl in all_canonical_acls(topology).items():
            zone = topology.zone(zone_key)
            if zone.vlan is None or not device.has_vlan(zone.vlan):
                continue
            expected_rules = [r.render().strip() for r in acl.rules]
            actual_rules = parsed.acls.get(acl.acl_number, [])
            if actual_rules != expected_rules:
                issues.append(
                    f"ACL {acl.acl_number}（zone-{zone_key}）与规范规则不一致："
                    f"配置 {len(actual_rules)} 条，规范 {len(expected_rules)} 条"
                )
            svi = parsed.interfaces.get(f"Vlanif{zone.vlan}")
            if svi is None or svi.acl != acl.acl_number:
                issues.append(
                    f"Vlanif{zone.vlan} 未正确引用 ACL {acl.acl_number}"
                )

    # 7) NAT
    if topology.nat and topology.nat.enabled and topology.nat.device == device.name:
        expected_nat_rules = [r.render().strip() for r in nat_acl_rules(topology)]
        actual = parsed.acls.get(topology.nat.acl_id, [])
        if actual != expected_nat_rules:
            issues.append(
                f"NAT ACL {topology.nat.acl_id} 不一致："
                f"配置 {actual}，规范 {expected_nat_rules}"
            )
        public = parsed.interfaces.get(_hw_iface(topology.nat.public_interface))
        if public is None or public.nat_acl != topology.nat.acl_id:
            issues.append(
                f"公网口 {topology.nat.public_interface} 未引用 nat outbound {topology.nat.acl_id}"
            )

    # 8) 运维要求
    if topology.operations.ntp_required and not parsed.has_ntp:
        issues.append("缺少 NTP 服务器配置")
    if topology.operations.logging_required and not parsed.has_loghost:
        issues.append("缺少日志服务器（info-center loghost）配置")

    return issues


def check_all_configs(topology: Topology, configs: Dict[str, str]) -> Dict[str, List[str]]:
    """逐台校验，返回 {设备名: [问题]}，无问题的设备不出现在结果里。"""
    result: Dict[str, List[str]] = {}
    for name, device in topology.devices.items():
        text = configs.get(name)
        if text is None:
            result[name] = ["没有生成该设备的配置"]
            continue
        issues = check_config(topology, device, text)
        if issues:
            result[name] = issues
    return result
