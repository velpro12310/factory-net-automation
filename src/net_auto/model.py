"""拓扑数据模型。

把 YAML 里的事实（设备、接口、VLAN、IP、策略）变成带行为的对象，
让上层（生成器 / 可达性引擎 / 校验器）只跟模型打交道，不直接摸字典。

为什么用 dataclass 而不是裸 dict：
  * 字段名写错会在构造时报错，而不是「静默取到 None，然后得出错误结论」——
    网络自动化里最危险的就是「校验跑过了但校验的是空值」。
  * ``frozen=True`` 的对象可以安全地在多份推导结果之间共享，
    故障注入必须走「拷贝 + 变异」，不能就地改模型。
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field, replace
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------- #
# 基础件
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class VlanDef:
    id: int
    name: str
    description: str = ""


@dataclass(frozen=True)
class Zone:
    key: str
    name: str
    vlan: Optional[int]
    prefix: str
    gateway: Optional[str]
    description: str = ""

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.prefix, strict=False)

    def contains(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in self.network
        except ValueError:
            return False

    @property
    def wildcard(self) -> str:
        """ACL 通配符掩码（反掩码）。华为 ACL 用反掩码而不是掩码。"""
        net = self.network
        packed = int(net.netmask)
        wild = packed ^ 0xFFFFFFFF
        return str(ipaddress.IPv4Address(wild))


@dataclass(frozen=True)
class ServiceDef:
    name: str
    protocol: str            # tcp | udp | icmp | any
    port: Optional[int]
    description: str = ""


@dataclass(frozen=True)
class Interface:
    name: str
    type: str                # access | trunk | routed
    peer: str = ""
    vlan: Optional[int] = None
    allow_vlans: Tuple[int, ...] = ()
    ip: Optional[str] = None
    is_public: bool = False
    description: str = ""

    @property
    def peer_device(self) -> str:
        return self.peer.split(":")[0] if ":" in self.peer else self.peer

    @property
    def peer_port(self) -> str:
        return self.peer.split(":", 1)[1] if ":" in self.peer else ""

    @property
    def network(self) -> Optional[ipaddress.IPv4Network]:
        if not self.ip:
            return None
        return ipaddress.ip_interface(self.ip).network

    def allows_vlan(self, vlan: int) -> bool:
        return self.type == "trunk" and vlan in self.allow_vlans


@dataclass(frozen=True)
class StaticRoute:
    dest: str
    next_hop: str
    metric: int = 60
    description: str = ""

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.dest, strict=False)


@dataclass(frozen=True)
class VrrpEntry:
    vrid: int
    vlan: int
    virtual_ip: str
    priority: int
    preempt_delay: int = 20


@dataclass(frozen=True)
class Svi:
    vlan: int
    ip: str

    @property
    def interface(self) -> ipaddress.IPv4Interface:
        return ipaddress.ip_interface(self.ip)

    @property
    def network(self) -> ipaddress.IPv4Network:
        return self.interface.network


@dataclass
class Device:
    name: str
    role: str                # core | access | router
    model: str
    management_ip: str
    description: str = ""
    vlans: List[int] = field(default_factory=list)
    svis: List[Svi] = field(default_factory=list)
    vrrp: List[VrrpEntry] = field(default_factory=list)
    interfaces: List[Interface] = field(default_factory=list)
    static_routes: List[StaticRoute] = field(default_factory=list)
    management: Dict[str, bool] = field(default_factory=dict)

    # -- 查询 ------------------------------------------------------------- #
    def iface(self, name: str) -> Optional[Interface]:
        for item in self.interfaces:
            if item.name == name:
                return item
        return None

    def trunks(self) -> List[Interface]:
        return [i for i in self.interfaces if i.type == "trunk"]

    def access_ports(self) -> List[Interface]:
        return [i for i in self.interfaces if i.type == "access"]

    def routed_ports(self) -> List[Interface]:
        return [i for i in self.interfaces if i.type == "routed"]

    def svi_for(self, vlan: int) -> Optional[Svi]:
        for item in self.svis:
            if item.vlan == vlan:
                return item
        return None

    def has_vlan(self, vlan: int) -> bool:
        return vlan in self.vlans

    def vrrp_for(self, vlan: int) -> Optional[VrrpEntry]:
        for item in self.vrrp:
            if item.vlan == vlan:
                return item
        return None

    def connected_networks(self) -> List[ipaddress.IPv4Network]:
        nets = [s.network for s in self.svis]
        nets += [i.network for i in self.routed_ports() if i.network is not None]
        return nets

    def is_managed(self, method: str) -> bool:
        return bool(self.management.get(method, False))


@dataclass(frozen=True)
class Host:
    name: str
    zone: str
    ip: str
    attached_to: Optional[str]
    port: Optional[str]
    role: str = ""

    @property
    def is_internal(self) -> bool:
        return self.attached_to is not None

    @property
    def address(self) -> ipaddress.IPv4Address:
        return ipaddress.ip_address(self.ip)


@dataclass(frozen=True)
class SecurityPolicy:
    id: int
    from_zone: str
    to_zone: str
    action: str                       # permit | deny
    protocol: str = "any"
    ports: Optional[Tuple[int, ...]] = None
    desc: str = ""

    def matches(self, from_zone: str, to_zone: str, protocol: str,
                port: Optional[int]) -> bool:
        """判断一条流是否命中本策略。``any`` 表示通配。"""
        if self.from_zone != "any" and self.from_zone != from_zone:
            return False
        if self.to_zone != "any" and self.to_zone != to_zone:
            return False
        if self.protocol != "any" and self.protocol != protocol:
            return False
        if self.ports and port is not None and port not in self.ports:
            return False
        if self.ports and port is None:
            # 策略限定了端口，但流没有端口（例如 ICMP）-> 视为不匹配
            return False
        return True


@dataclass(frozen=True)
class NatConfig:
    enabled: bool
    device: str
    acl_id: int
    public_interface: str
    mode: str
    allowed_zones: Tuple[str, ...]
    description: str = ""

    def allows_zone(self, zone: str) -> bool:
        return self.enabled and zone in self.allowed_zones


@dataclass(frozen=True)
class Operations:
    logging_required: bool = False
    logging_server: str = ""
    ntp_required: bool = False
    ntp_server: str = ""
    backup_required: bool = False


# --------------------------------------------------------------------------- #
# 拓扑容器
# --------------------------------------------------------------------------- #
class Topology:
    """一份完整的网络拓扑。所有查询集中在这里，上层不直接遍历字典。"""

    def __init__(
        self,
        meta: Dict,
        zones: Sequence[Zone],
        vlans: Sequence[VlanDef],
        services: Sequence[ServiceDef],
        hosts: Sequence[Host],
        devices: Sequence[Device],
        policies: Sequence[SecurityPolicy],
        nat: Optional[NatConfig],
        operations: Operations,
        vrrp_groups: Sequence[dict],
    ) -> None:
        self.meta = dict(meta)
        self.zones: Dict[str, Zone] = {z.key: z for z in zones}
        self.vlans: Dict[int, VlanDef] = {v.id: v for v in vlans}
        self.services: Dict[str, ServiceDef] = {s.name: s for s in services}
        self.hosts: Dict[str, Host] = {h.name: h for h in hosts}
        self.devices: Dict[str, Device] = {d.name: d for d in devices}
        self.policies: List[SecurityPolicy] = sorted(policies, key=lambda p: p.id)
        self.nat = nat
        self.operations = operations
        self.vrrp_groups = list(vrrp_groups)

    # -- 深拷贝：故障注入必须基于副本变异，不能污染原始模型 --------------- #
    def clone(self) -> "Topology":
        import copy

        return copy.deepcopy(self)

    # -- 查询 ------------------------------------------------------------- #
    def zone(self, key: str) -> Zone:
        if key not in self.zones:
            raise KeyError(f"未定义的安全域：{key}")
        return self.zones[key]

    def zone_of_ip(self, ip: str) -> Optional[Zone]:
        for zone in self.zones.values():
            if zone.key == "internet":
                continue
            if zone.contains(ip):
                return zone
        return None

    def zone_by_vlan(self, vlan: int) -> Optional[Zone]:
        for zone in self.zones.values():
            if zone.vlan == vlan:
                return zone
        return None

    def host(self, name: str) -> Host:
        if name not in self.hosts:
            raise KeyError(f"未定义的端系统：{name}")
        return self.hosts[name]

    def device(self, name: str) -> Device:
        if name not in self.devices:
            raise KeyError(f"未定义的设备：{name}")
        return self.devices[name]

    def service(self, name: str) -> ServiceDef:
        if name not in self.services:
            raise KeyError(f"未定义的服务：{name}")
        return self.services[name]

    def host_zone(self, name: str) -> str:
        return self.host(name).zone

    def zone_name(self, key: str) -> str:
        return self.zones[key].name if key in self.zones else key

    def vrrp_for_vlan(self, vlan: int) -> Optional[dict]:
        for group in self.vrrp_groups:
            if group.get("vlan") == vlan:
                return group
        return None

    def gateway_for_zone(self, key: str) -> Optional[str]:
        return self.zones[key].gateway if key in self.zones else None

    def devices_with_role(self, role: str) -> List[Device]:
        return [d for d in self.devices.values() if d.role == role]

    def cores(self) -> List[Device]:
        return self.devices_with_role("core")

    def interface_between(self, device_a: str, port_a: str,
                          device_b: str, port_b: str) -> Tuple[Optional[Interface], Optional[Interface]]:
        a = self.devices.get(device_a)
        b = self.devices.get(device_b)
        ia = a.iface(port_a) if a else None
        ib = b.iface(port_b) if b else None
        return ia, ib

    # -- 匹配策略表 ------------------------------------------------------- #
    def resolve_policy(self, from_zone: str, to_zone: str, protocol: str,
                       port: Optional[int]) -> Optional[SecurityPolicy]:
        """按顺序返回首条命中的策略；无命中返回 None（表示落到隐式默认拒绝）。"""
        for policy in self.policies:
            if policy.matches(from_zone, to_zone, protocol, port):
                return policy
        return None

    # -- 结构自检 --------------------------------------------------------- #
    def structural_issues(self) -> List[str]:
        """拓扑级自检：连线是否双向一致、IP 是否重复、VLAN 是否已定义等。

        这一步在生成配置之前跑，把「数据本身的错误」和「配置生成的错误」分开，
        否则一个 IP 写错会表现成十几条配置差异，排查成本成倍上升。
        """
        issues: List[str] = []

        # 1) 连线双向一致性（对端可能是网络设备，也可能是端系统）
        for device in self.devices.values():
            for iface in device.interfaces:
                if not iface.peer or iface.peer == "Internet":
                    continue
                peer_dev, _, peer_port = iface.peer.partition(":")
                if peer_dev in self.hosts:
                    # 对端是端系统（接入口）：由下面「主机接入口校验」统一负责，
                    # 这里不能按设备规则判，否则每台主机都会误报一条
                    continue
                if peer_dev not in self.devices:
                    issues.append(f"{device.name}:{iface.name} 的对端设备 {peer_dev} 不存在")
                    continue
                back = self.devices[peer_dev].iface(peer_port)
                if back is None:
                    issues.append(
                        f"{device.name}:{iface.name} 对端 {iface.peer} 上不存在该接口"
                    )
                elif back.peer.split(":")[0] != device.name or back.peer.split(":")[-1] != iface.name:
                    issues.append(
                        f"连线不对称：{device.name}:{iface.name} -> {iface.peer}，"
                        f"但对端指向 {back.peer}"
                    )

        # 2) VLAN 必须先定义
        for device in self.devices.values():
            for vlan in device.vlans:
                if vlan not in self.vlans:
                    issues.append(f"{device.name}: 使用了未定义的 VLAN {vlan}")
            for iface in device.interfaces:
                if iface.type == "access" and iface.vlan not in self.vlans:
                    issues.append(
                        f"{device.name}:{iface.name}: access 口划入未定义的 VLAN {iface.vlan}"
                    )
                for vlan in iface.allow_vlans:
                    if vlan not in self.vlans:
                        issues.append(
                            f"{device.name}:{iface.name}: trunk 放行了未定义的 VLAN {vlan}"
                        )

        # 3) 每个业务域必须有网关，且网关落在某个核心上
        for zone in self.zones.values():
            if zone.vlan is None:
                continue
            if zone.gateway is None:
                issues.append(f"安全域 {zone.key} 未定义网关")
                continue
            hosts_ok = any(
                d.svi_for(zone.vlan) is not None for d in self.cores()
            )
            if not hosts_ok:
                issues.append(f"安全域 {zone.key}（VLAN {zone.vlan}）在核心交换机上没有 SVI")

        # 3b) VRRP 组完整性：主备设备都必须有对应的 SVI 与 VRRP 实例
        #
        # 注意这里与可达性推导的分工：
        #   * 主设备缺 SVI 在真实环境会触发备设备接管，业务不一定中断，
        #     所以可达性引擎只要求「至少一台核心有 SVI」；
        #   * 但它说明**配置下发不完整**，属于必须修掉的配置不一致，放在这里报。
        # 这个区分很关键：把「业务影响」与「配置正确性」混在一起判，
        # 会出现「网络其实是通的，工具却报不可达」的误报，久了就没人信工具了。
        for group in self.vrrp_groups:
            vlan = group.get("vlan")
            vrid = group.get("vrid")
            vip = group.get("virtual_ip")
            for role in ("master", "backup"):
                name = group.get(role)
                if not name:
                    continue
                device = self.devices.get(name)
                if device is None:
                    issues.append(f"VRRP 组 {vrid} 的 {role} 设备 {name} 不存在")
                    continue
                if device.svi_for(vlan) is None:
                    issues.append(
                        f"VRRP 组 {vrid}（VLAN {vlan}）的 {role} 设备 {device.name} 缺少 SVI"
                    )
                    continue
                entry = device.vrrp_for(vlan)
                if entry is None:
                    issues.append(
                        f"VRRP 组 {vrid}（VLAN {vlan}）的 {role} 设备 {device.name} 缺少 VRRP 实例"
                    )
                elif entry.virtual_ip != vip:
                    issues.append(
                        f"VRRP 组 {vrid} 的虚拟地址不一致：{device.name} 上是 "
                        f"{entry.virtual_ip}，VRRP 清单是 {vip}"
                    )

        # 4) IP 地址冲突
        #    同一台设备的「管理口地址」与「管理 VLAN 的 SVI 地址」本来就是同一个 IP，
        #    不算冲突；只有跨设备重号才是真冲突。
        seen: Dict[str, str] = {}

        def register(ip: str, owner: str, device: str = "") -> None:
            previous = seen.get(ip)
            if previous is None:
                seen[ip] = owner
                return
            if device and previous.startswith(f"{device}:"):
                return
            issues.append(f"IP 冲突：{ip} 同时被 {previous} 与 {owner} 使用")

        for host in self.hosts.values():
            if host.is_internal:
                register(host.ip, host.name)
        for device in self.devices.values():
            for svi in device.svis:
                register(str(svi.interface.ip), f"{device.name}:Vlanif{svi.vlan}", device.name)
            for iface in device.routed_ports():
                if iface.ip:
                    register(str(ipaddress.ip_interface(iface.ip).ip),
                             f"{device.name}:{iface.name}", device.name)
            register(device.management_ip, f"{device.name}(管理口)", device.name)

        # 5) VRRP 虚拟地址不能与任何实体地址冲突
        for group in self.vrrp_groups:
            vip = group.get("virtual_ip")
            if not vip:
                continue
            if vip in seen:
                issues.append(f"VRRP 虚拟地址 {vip} 与 {seen[vip]} 冲突")
            else:
                seen[vip] = f"VRRP-{group.get('vrid')}"

        # 6) 主机接入端口必须真实存在且 VLAN 与所属域一致
        for host in self.hosts.values():
            if not host.is_internal:
                continue
            device = self.devices.get(host.attached_to or "")
            if device is None:
                issues.append(f"{host.name} 接入的设备 {host.attached_to} 不存在")
                continue
            iface = device.iface(host.port or "")
            if iface is None:
                issues.append(f"{host.name} 接入的端口 {host.attached_to}:{host.port} 不存在")
                continue
            if iface.type != "access":
                issues.append(
                    f"{host.name} 接入的是 {iface.type} 口（应为 access）：{host.attached_to}:{iface.name}"
                )
            expected_vlan = self.zones[host.zone].vlan
            if iface.vlan != expected_vlan:
                issues.append(
                    f"{host.name}（域 {host.zone}）接入端口的 VLAN 是 {iface.vlan}，"
                    f"与所属域的 VLAN {expected_vlan} 不一致"
                )

        # 7) 安全策略表必须有序放通在前、且有兜底默认拒绝
        if not self.policies:
            issues.append("安全策略表为空")
        elif not (self.policies[-1].from_zone == "any"
                  and self.policies[-1].to_zone == "any"
                  and self.policies[-1].action == "deny"):
            issues.append("安全策略表最后一条不是「any -> any 拒绝」兜底规则")

        # 8) NAT 允许的区域必须真实存在
        if self.nat and self.nat.enabled:
            for zone in self.nat.allowed_zones:
                if zone not in self.zones:
                    issues.append(f"NAT 允许的区域 {zone} 未定义")

        # 9) 操作要求引用的服务器必须存在
        if self.operations.logging_required and self.operations.logging_server:
            if self.operations.logging_server not in self.hosts:
                issues.append(
                    f"日志服务器 {self.operations.logging_server} 不在端系统清单中"
                )

        return issues

    # -- 便捷：把路由表摊平成 (前缀, 下一跳, 度量) 列表 -------------------- #
    def routes_of(self, device_name: str) -> List[Tuple[ipaddress.IPv4Network, str, int]]:
        device = self.device(device_name)
        rows: List[Tuple[ipaddress.IPv4Network, str, int]] = []
        for net in device.connected_networks():
            rows.append((net, "directly-connected", 0))
        for route in device.static_routes:
            rows.append((route.network, route.next_hop, route.metric))
        rows.sort(key=lambda item: (item[0].prefixlen, item[2]), reverse=True)
        return rows
