"""配置生成器：拓扑模型 + Jinja2 模板 -> 华为 VRP 配置。

「配置即代码」落地在这一层。它要同时满足三个要求：

  1. **可重复**：同一份拓扑重复生成，输出必须逐字节一致（不含时间戳以外的随机量）。
     否则「配置比对」这种最基础的运维手段就没法用了。
  2. **可追溯**：每台设备的配置文件头部写明拓扑版本与生成时间，
     并明确标注「请勿手工修改」——手工改动是配置漂移的根源。
  3. **生成前自检**：拓扑有结构问题时直接拒绝生成。
     一个写错的 IP 如果混进配置，会表现成十几条配置差异，排查成本成倍上升。

ACL 只下发在核心交换机上（它们是各 VLAN 的网关，域间流量必经此地）；
接入交换机只做二层转发与带外管理，出口路由器负责 NAT。
这是标准的「三层到核心、二层到接入」工厂网设计。
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from .acl import CanonicalAcl, all_canonical_acls, nat_acl_rules
from .model import Device, Topology
from .loader import PROJECT_ROOT

TEMPLATE_DIR = PROJECT_ROOT / "templates"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "output"

#: 角色 -> 模板文件
TEMPLATE_BY_ROLE = {
    "core": "core_switch.j2",
    "access": "access_switch.j2",
    "router": "router.j2",
}

#: 接口名前缀 -> 华为完整接口名
IFACE_PREFIX = {
    "GE": "GigabitEthernet",
    "XGE": "XGigabitEthernet",
    "10GE": "XGigabitEthernet",
    "ETH": "Ethernet",
    "LoopBack": "LoopBack",
}


class GenerationError(Exception):
    """生成阶段发现的错误（拓扑不自检、模板缺失、角色无对应模板）。"""


def _split_cidr(cidr: str) -> tuple[str, str]:
    """``10.10.10.252/24`` -> ``("10.10.10.252", "255.255.255.0")``"""
    iface = ipaddress.ip_interface(cidr)
    return str(iface.ip), str(iface.netmask)


def _route_mask(dest: str) -> tuple[str, str]:
    net = ipaddress.ip_network(dest, strict=False)
    return str(net.network_address), str(net.netmask)


def _hw_iface(name: str) -> str:
    """``GE0/0/1`` -> ``GigabitEthernet0/0/1``"""
    for prefix, full in sorted(IFACE_PREFIX.items(), key=lambda kv: -len(kv[0])):
        if name.startswith(prefix):
            return full + name[len(prefix):]
    return name


# --------------------------------------------------------------------------- #
def build_context(topology: Topology, device: Device, generated_at: str) -> Dict[str, Any]:
    """把模型摊平成一个「模板好写」的上下文。"""
    acls: List[CanonicalAcl] = []
    acl_by_vlan: Dict[int, int] = {}
    if device.role == "core":
        cache = all_canonical_acls(topology)
        for zone_key, acl in cache.items():
            zone = topology.zone(zone_key)
            if zone.vlan is not None and device.has_vlan(zone.vlan):
                acls.append(acl)
                acl_by_vlan[zone.vlan] = acl.acl_number

    # SVI + VRRP
    svis: List[Dict[str, Any]] = []
    for svi in device.svis:
        addr, mask = _split_cidr(svi.ip)
        zone = topology.zone_by_vlan(svi.vlan)
        svis.append({
            "vlan": svi.vlan,
            "addr": addr,
            "mask": mask,
            "description": zone.name if zone else f"VLAN {svi.vlan}",
            "acl": acl_by_vlan.get(svi.vlan),
            "vrrp": [
                {
                    "vrid": v.vrid, "virtual_ip": v.virtual_ip,
                    "priority": v.priority, "preempt_delay": v.preempt_delay,
                }
                for v in device.vrrp if v.vlan == svi.vlan
            ],
        })

    # 物理接口
    interfaces: List[Dict[str, Any]] = []
    for iface in device.interfaces:
        addr = mask = None
        if iface.ip:
            addr, mask = _split_cidr(iface.ip)
        interfaces.append({
            "name": _hw_iface(iface.name),
            "type": iface.type,
            "peer": iface.peer,
            "description": iface.description,
            # 描述在这里拼好，不在模板里用行内 {% if %}。
            # 原因：Jinja 的 trim_blocks 会把**行内**块标签后的换行也吃掉，
            # 行内写 if 会让 description 与下一行粘连，生成出语法错误的配置。
            "desc_full": (f"To {iface.peer}"
                          + (f" / {iface.description}" if iface.description else "")),
            "vlan": iface.vlan,
            "allow_vlans": list(iface.allow_vlans),
            "addr": addr,
            "mask": mask,
            "is_public": iface.is_public,
        })

    # 静态路由
    routes: List[Dict[str, Any]] = []
    for route in device.static_routes:
        network, mask = _route_mask(route.dest)
        routes.append({
            "network": network, "mask": mask,
            "next_hop": route.next_hop,
            "preference": route.metric,
            "description": route.description,
        })

    # NAT（仅出口路由器）
    nat_ctx = None
    if topology.nat and topology.nat.enabled and topology.nat.device == device.name:
        public_iface = device.iface(topology.nat.public_interface)
        nat_ctx = {
            "acl_id": topology.nat.acl_id,
            "mode": topology.nat.mode,
            "public_interface": _hw_iface(topology.nat.public_interface),
            "public_ip": str(ipaddress.ip_interface(public_iface.ip).ip) if public_iface and public_iface.ip else "",
            "allowed_zones": list(topology.nat.allowed_zones),
            "rules": [
                {"seq": r.seq, "action": r.action,
                 "source_prefix": r.source_prefix.split("/")[0],
                 "wildcard": r.source_wildcard, "zone": r.zone_key}
                for r in nat_acl_rules(topology)
            ],
        }

    # 运维参数
    def host_ip(name: str) -> str:
        host = topology.hosts.get(name)
        return host.ip if host else ""

    ops = {
        "loghost": host_ip(topology.operations.logging_server),
        "ntp_server": topology.operations.ntp_server,
        "logging_required": topology.operations.logging_required,
        "ntp_required": topology.operations.ntp_required,
    }

    return {
        "device": device,
        "meta": topology.meta,
        "generated_at": generated_at,
        "svis": svis,
        "interfaces": interfaces,
        "routes": routes,
        "acls": acls,
        "nat": nat_ctx,
        "ops": ops,
    }


def build_environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        undefined=StrictUndefined,       # 模板里写错变量名要立刻炸，不能静默输出空值
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        autoescape=select_autoescape(enabled_extensions=(), default=False),
    )
    return env


def render_device(topology: Topology, device: Device, generated_at: str,
                  env: Optional[Environment] = None) -> str:
    if device.role not in TEMPLATE_BY_ROLE:
        raise GenerationError(
            f"设备 {device.name} 的角色 {device.role} 没有对应模板，"
            f"可选角色：{sorted(TEMPLATE_BY_ROLE)}"
        )
    env = env or build_environment()
    template = env.get_template(TEMPLATE_BY_ROLE[device.role])
    return template.render(**build_context(topology, device, generated_at))


def generate_configs(topology: Topology, generated_at: str,
                     force: bool = False) -> Dict[str, str]:
    """生成全部设备配置。默认在生成前做拓扑自检。"""
    issues = topology.structural_issues()
    if issues and not force:
        joined = "\n  - ".join(issues)
        raise GenerationError(f"拓扑自检未通过，已拒绝生成配置：\n  - {joined}")

    env = build_environment()
    return {
        device.name: render_device(topology, device, generated_at, env)
        for device in topology.devices.values()
    }


def write_configs(configs: Dict[str, str], out_dir: str | Path | None = None) -> List[Path]:
    target = Path(out_dir or DEFAULT_OUTPUT_DIR) / "configs"
    target.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    for name, text in configs.items():
        path = target / f"{name}.cfg"
        path.write_text(text, encoding="utf-8", newline="\n")
        written.append(path)
    return written


def config_stats(configs: Dict[str, str]) -> Dict[str, Any]:
    """给报告用的配置概览。"""
    return {
        "devices": len(configs),
        "lines": sum(len(text.splitlines()) for text in configs.values()),
        "bytes": sum(len(text.encode("utf-8")) for text in configs.values()),
        "per_device": {name: len(text.splitlines()) for name, text in configs.items()},
    }
