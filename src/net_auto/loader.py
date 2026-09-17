"""拓扑加载：YAML -> Topology 模型。

加载阶段做两件事：
  1. 结构转换（把 dict 变成带行为的 dataclass）
  2. **结构自检**——连线是否双向一致、IP 是否冲突、主机接入口 VLAN 是否对得上。
     这一步必须前置于配置生成：数据本身的错误如果混进配置，
     一个写错的 IP 会表现成十几条配置差异，排查成本成倍上升。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .model import (
    Device,
    Host,
    Interface,
    NatConfig,
    Operations,
    SecurityPolicy,
    ServiceDef,
    Svi,
    StaticRoute,
    Topology,
    VlanDef,
    VrrpEntry,
    Zone,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TOPOLOGY_PATH = PROJECT_ROOT / "topology" / "smart_factory.yaml"
DEFAULT_EXPECTATION_PATH = PROJECT_ROOT / "topology" / "expectations.yaml"


class TopologyError(Exception):
    """拓扑数据本身有问题，无法继续。"""


def load_yaml(path: str | Path) -> Dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


# --------------------------------------------------------------------------- #
def _build_zone(item: Dict) -> Zone:
    return Zone(
        key=item["key"],
        name=item.get("name", item["key"]),
        vlan=item.get("vlan"),
        prefix=item["prefix"],
        gateway=item.get("gateway"),
        description=item.get("description", ""),
    )


def _build_service(item: Dict) -> ServiceDef:
    return ServiceDef(
        name=item["name"],
        protocol=str(item.get("protocol", "any")).lower(),
        port=item.get("port"),
        description=item.get("description", ""),
    )


def _build_host(item: Dict) -> Host:
    return Host(
        name=item["name"],
        zone=item["zone"],
        ip=item["ip"],
        attached_to=item.get("attached_to"),
        port=item.get("port"),
        role=item.get("role", ""),
    )


def _build_interface(item: Dict) -> Interface:
    iface_type = str(item.get("type", "access")).lower()
    return Interface(
        name=item["name"],
        type=iface_type,
        peer=item.get("peer", ""),
        vlan=item.get("vlan"),
        allow_vlans=tuple(item.get("allow_vlans", []) or []),
        ip=item.get("ip"),
        is_public=bool(item.get("is_public", False)),
        description=item.get("description", ""),
    )


def _build_device(item: Dict) -> Device:
    return Device(
        name=item["name"],
        role=item["role"],
        model=item.get("model", ""),
        management_ip=item["management_ip"],
        description=item.get("description", ""),
        vlans=list(item.get("vlans", []) or []),
        svis=[Svi(vlan=s["vlan"], ip=s["ip"]) for s in item.get("svis", []) or []],
        vrrp=[VrrpEntry(
            vrid=v["vrid"], vlan=v["vlan"], virtual_ip=v["virtual_ip"],
            priority=v["priority"], preempt_delay=v.get("preempt_delay", 20),
        ) for v in item.get("vrrp", []) or []],
        interfaces=[_build_interface(i) for i in item.get("interfaces", []) or []],
        static_routes=[StaticRoute(
            dest=r["dest"], next_hop=r["next_hop"],
            metric=r.get("metric", 60), description=r.get("description", ""),
        ) for r in item.get("static_routes", []) or []],
        management=dict(item.get("management", {}) or {}),
    )


def _build_policy(item: Dict) -> SecurityPolicy:
    ports = item.get("ports")
    return SecurityPolicy(
        id=int(item["id"]),
        from_zone=item["from"],
        to_zone=item["to"],
        action=str(item["action"]).lower(),
        protocol=str(item.get("protocol", "any")).lower(),
        ports=tuple(ports) if ports else None,
        desc=item.get("desc", ""),
    )


def _build_nat(item: Optional[Dict]) -> Optional[NatConfig]:
    if not item:
        return None
    return NatConfig(
        enabled=bool(item.get("enabled", False)),
        device=item.get("device", ""),
        acl_id=int(item.get("acl_id", 2000)),
        public_interface=item.get("public_interface", ""),
        mode=item.get("mode", "pat"),
        allowed_zones=tuple(item.get("allowed_zones", []) or []),
        description=item.get("description", ""),
    )


def _build_operations(item: Optional[Dict]) -> Operations:
    if not item:
        return Operations()
    logging_cfg = item.get("logging", {}) or {}
    ntp_cfg = item.get("ntp", {}) or {}
    backup_cfg = item.get("config_backup", {}) or {}
    return Operations(
        logging_required=bool(logging_cfg.get("required", False)),
        logging_server=logging_cfg.get("server", ""),
        ntp_required=bool(ntp_cfg.get("required", False)),
        ntp_server=ntp_cfg.get("server", ""),
        backup_required=bool(backup_cfg.get("required", False)),
    )


# --------------------------------------------------------------------------- #
def build_topology(raw: Dict[str, Any]) -> Topology:
    return Topology(
        meta=raw.get("meta", {}),
        zones=[_build_zone(z) for z in raw.get("zones", [])],
        vlans=[VlanDef(id=v["id"], name=v.get("name", ""), description=v.get("description", ""))
               for v in raw.get("vlans", [])],
        services=[_build_service(s) for s in raw.get("services", [])],
        hosts=[_build_host(h) for h in raw.get("hosts", [])],
        devices=[_build_device(d) for d in raw.get("devices", [])],
        policies=[_build_policy(p) for p in raw.get("security_policies", [])],
        nat=_build_nat(raw.get("nat")),
        operations=_build_operations(raw.get("operations")),
        vrrp_groups=raw.get("vrrp_groups", []) or [],
    )


def load_topology(path: str | Path | None = None, strict: bool = True) -> Topology:
    """加载拓扑。``strict=True`` 时结构自检不通过就抛错。"""
    topology = build_topology(load_yaml(path or DEFAULT_TOPOLOGY_PATH))
    issues = topology.structural_issues()
    if issues and strict:
        joined = "\n  - ".join(issues)
        raise TopologyError(f"拓扑结构自检未通过：\n  - {joined}")
    return topology


def load_expectations(path: str | Path | None = None) -> Dict[str, Any]:
    return load_yaml(path or DEFAULT_EXPECTATION_PATH)


def load_faults(path: str | Path | None = None) -> List[Dict[str, Any]]:
    raw = load_yaml(path or (PROJECT_ROOT / "topology" / "faults.yaml"))
    return raw.get("faults", [])


def topology_summary(topology: Topology) -> Dict[str, Any]:
    """给报告用的概览数据。"""
    return {
        "name": topology.meta.get("name", ""),
        "site": topology.meta.get("site", ""),
        "version": topology.meta.get("version", ""),
        "zones": len(topology.zones),
        "vlans": len(topology.vlans),
        "devices": len(topology.devices),
        "hosts": len([h for h in topology.hosts.values() if h.is_internal]),
        "external_hosts": len([h for h in topology.hosts.values() if not h.is_internal]),
        "services": len(topology.services),
        "policies": len(topology.policies),
        "links": sum(len(d.interfaces) for d in topology.devices.values()) // 2,
        "vrrp_groups": len(topology.vrrp_groups),
    }
