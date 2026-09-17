"""ACL 规则模型：把「域间策略意图」翻译成「设备上实际下发的规则」。

两层东西必须分清：

    安全策略表（topology/security_policies）—— 设计意图，人读的
    ACL 规则（本模块产出的 AccessRule）    —— 设备落地，机器执行的

生成器的职责就是让这两层严格同源；校验器的职责是反过来把生成的配置解析回
规则，逐条比对，确保「文档写的」和「设备配的」没有漂移。

另外本模块负责**死规则检测**：被前面规则完全覆盖、永远不会命中的规则。
死规则不造成功能故障，但会让人误以为「这条策略生效了」——排障时按 ACL 顺序
逐条读会被带偏，所以要么消除，要么显式记录。
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, replace
from typing import Dict, List, Optional, Sequence, Tuple

from .model import SecurityPolicy, Topology, Zone

#: 各安全域对应的 ACL 编号（华为 ACL 序号即用途约定，10~99 基本 ACL，100~999 高级）
#: 3000+ 为高级 ACL（可匹配协议与端口），本工程用 3010/3020/3030/3040 分别对应四个域。
ACL_BASE = {
    "workshop": 3010,
    "office": 3020,
    "server": 3030,
    "mgmt": 3040,
}

#: 规则序号步长。华为设备按序号插入规则，留出步长便于后续增删。
SEQ_STEP = 5

PROTOCOL_ANY = "ip"

#: 兜底默认拒绝规则在策略表中的固定编号
DEFAULT_DENY_POLICY_ID = 90


def acl_number_for_zone(zone_key: str) -> int:
    if zone_key not in ACL_BASE:
        raise KeyError(f"安全域 {zone_key} 未分配 ACL 编号")
    return ACL_BASE[zone_key]


def _wildcard(ip: str, prefixlen: int) -> str:
    net = ipaddress.ip_network(f"{ip}/{prefixlen}", strict=False)
    return str(ipaddress.IPv4Address(int(net.netmask) ^ 0xFFFFFFFF))


# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class AccessRule:
    seq: int
    action: str                              # permit | deny
    protocol: str                            # ip | tcp | udp | icmp
    source_prefix: Optional[str] = None      # None 表示 any
    source_wildcard: Optional[str] = None
    dest_prefix: Optional[str] = None        # None 表示 any
    dest_wildcard: Optional[str] = None
    dest_port: Optional[int] = None
    policy_id: int = 0
    description: str = ""

    def render(self, indent: str = " ") -> str:
        """渲染成一行华为 VRP 配置。"""
        parts = [f"rule {self.seq} {self.action}"]
        parts.append(self.protocol)
        if self.source_prefix:
            parts.append(f"source {_net_addr(self.source_prefix)} {self.source_wildcard}")
        if self.dest_prefix:
            parts.append(f"destination {_net_addr(self.dest_prefix)} {self.dest_wildcard}")
        if self.dest_port is not None:
            parts.append(f"destination-port eq {self.dest_port}")
        return indent + " ".join(parts)

    def as_dict(self) -> dict:
        return {
            "seq": self.seq, "action": self.action, "protocol": self.protocol,
            "source": f"{self.source_prefix}/{self.source_wildcard}" if self.source_prefix else "any",
            "destination": f"{self.dest_prefix}/{self.dest_wildcard}" if self.dest_prefix else "any",
            "port": self.dest_port if self.dest_port is not None else "any",
            "policy_id": self.policy_id, "description": self.description,
        }


# --------------------------------------------------------------------------- #
# 覆盖关系（用于死规则检测）
# --------------------------------------------------------------------------- #
def _protocol_covers(outer: str, inner: str) -> bool:
    return outer == PROTOCOL_ANY or outer == inner


def _net_addr(prefix: str) -> str:
    """取出网段地址（不带掩码）。华为 ACL 的写法是 ``source 10.10.10.0 0.0.0.255``，
    地址与反掩码分开写，不能把 ``10.10.10.0/24`` 直接拼进去。"""
    return str(ipaddress.ip_network(prefix, strict=False).network_address)


def _prefix_covers(outer: Optional[str], inner: Optional[str]) -> bool:
    """outer 是否覆盖 inner（含两者相同的情况）。

    这里**不能用** ``ip_network(inner) in ip_network(outer)``：
    Python 的 ``IPv4Network.__contains__`` 只认**严格子网**，
    ``N in N`` 返回 False。用它会导致「完全相同的两条规则判不出覆盖」，
    死规则检测静默失效——本工程就是踩了这个坑才改成显式地址范围比较。
    """
    if outer is None:
        return True                      # any 覆盖一切
    if inner is None:
        return False
    outer_net = ipaddress.ip_network(outer, strict=False)
    inner_net = ipaddress.ip_network(inner, strict=False)
    if outer_net.version != inner_net.version:
        return False
    return (int(inner_net.network_address) >= int(outer_net.network_address)
            and int(inner_net.broadcast_address) <= int(outer_net.broadcast_address))


def rule_covers(outer: AccessRule, inner: AccessRule) -> bool:
    """outer 是否完全覆盖 inner（inner 永远不可能命中）。

    注意：与动作无关——前面的规则无论是 permit 还是 deny，
    只要匹配范围是超集，后面的规则就永远不会被执行到。
    """
    if not _protocol_covers(outer.protocol, inner.protocol):
        return False
    if not _prefix_covers(outer.source_prefix, inner.source_prefix):
        return False
    if not _prefix_covers(outer.dest_prefix, inner.dest_prefix):
        return False
    if outer.dest_port is None:
        return True
    return outer.dest_port == inner.dest_port


# --------------------------------------------------------------------------- #
# 策略 -> 规则
# --------------------------------------------------------------------------- #
def rules_from_policy(policy: SecurityPolicy, topology: Topology,
                      source_zone_key: str) -> List[AccessRule]:
    """把一条策略渲染成（可能多条）ACL 规则。

    一条策略里若写了多个端口，会拆成多条规则——这样每条规则只匹配一个端口，
    语义最清晰，也便于逐条比对与排查。
    """
    protocol = PROTOCOL_ANY if policy.protocol == "any" else policy.protocol
    source_zone: Zone = topology.zone(source_zone_key)
    source_prefix = source_zone.prefix
    source_wildcard = source_zone.wildcard

    if policy.to_zone in ("any", "internet"):
        dest_prefix = dest_wildcard = None
    else:
        dest_zone = topology.zone(policy.to_zone)
        dest_prefix = dest_zone.prefix
        dest_wildcard = dest_zone.wildcard

    ports: Sequence[Optional[int]] = tuple(policy.ports) if policy.ports else (None,)

    return [
        AccessRule(
            seq=0,                                   # 编号在 canonicalize 阶段统一分配
            action=policy.action,
            protocol=protocol,
            source_prefix=source_prefix,
            source_wildcard=source_wildcard,
            dest_prefix=dest_prefix,
            dest_wildcard=dest_wildcard,
            dest_port=port,
            policy_id=policy.id,
            description=policy.desc,
        )
        for port in ports
    ]


@dataclass(frozen=True)
class CanonicalAcl:
    """一个域最终要下发的 ACL。"""

    zone_key: str
    acl_number: int
    rules: Tuple[AccessRule, ...]
    dropped: Tuple[AccessRule, ...] = ()            # 被判定为死规则而剔除的（不含兜底）
    shadowed_default_deny: bool = False             # 兜底拒绝已被 catch-all 放通规则遮蔽

    @property
    def permit_count(self) -> int:
        return sum(1 for r in self.rules if r.action == "permit")

    @property
    def deny_count(self) -> int:
        return sum(1 for r in self.rules if r.action == "deny")

    def render(self) -> List[str]:
        return [f"acl number {self.acl_number}"] + [r.render() for r in self.rules]


def _is_catch_all_deny(rule: AccessRule) -> bool:
    """判断一条规则是否是「拒绝一切」——即可以充当兜底默认拒绝。"""
    return (rule.action == "deny" and rule.protocol == PROTOCOL_ANY
            and rule.dest_prefix is None and rule.dest_port is None)


def canonical_acl(topology: Topology, zone_key: str) -> CanonicalAcl:
    """生成某个域的规范 ACL：按策略顺序展开、剔除死规则、保证有兜底拒绝。

    剔死规则是**安全动作**而不是「省几条配置」：
    留着一条永远不会命中的 permit 规则，会让人在排障时误判「这条路是通的」。

    兜底默认拒绝单独处理：如果它已被前面某条 catch-all 拒绝规则覆盖，
    就不重复下发（记入 ``shadowed_default_deny``，报告里会说明原因）。
    """
    raw: List[AccessRule] = []
    for policy in topology.policies:
        if policy.from_zone not in (zone_key, "any"):
            continue
        raw.extend(rules_from_policy(policy, topology, zone_key))

    default_deny_rules = [r for r in raw if r.policy_id == DEFAULT_DENY_POLICY_ID]
    body = [r for r in raw if r.policy_id != DEFAULT_DENY_POLICY_ID]

    kept: List[AccessRule] = []
    dropped: List[AccessRule] = []
    for rule in body:
        if any(rule_covers(k, rule) for k in kept):
            dropped.append(rule)
        else:
            kept.append(rule)

    shadowed = False
    if any(_is_catch_all_deny(r) for r in kept):
        shadowed = True
    elif default_deny_rules:
        kept.append(default_deny_rules[0])
    else:
        zone = topology.zone(zone_key)
        kept.append(AccessRule(
            seq=0, action="deny", protocol=PROTOCOL_ANY,
            source_prefix=zone.prefix, source_wildcard=zone.wildcard,
            policy_id=DEFAULT_DENY_POLICY_ID, description="默认拒绝并记录日志",
        ))

    numbered = tuple(
        replace(rule, seq=SEQ_STEP * (index + 1)) for index, rule in enumerate(kept)
    )
    return CanonicalAcl(
        zone_key=zone_key,
        acl_number=acl_number_for_zone(zone_key),
        rules=numbered,
        dropped=tuple(dropped),
        shadowed_default_deny=shadowed,
    )


def all_canonical_acls(topology: Topology) -> Dict[str, CanonicalAcl]:
    return {key: canonical_acl(topology, key) for key in ACL_BASE}


# --------------------------------------------------------------------------- #
# NAT 用的基本 ACL（只匹配源地址）
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class NatAclRule:
    seq: int
    action: str
    source_prefix: str
    source_wildcard: str
    zone_key: str

    def render(self, indent: str = " ") -> str:
        return (f"{indent}rule {self.seq} {self.action} source "
                f"{_net_addr(self.source_prefix)} {self.source_wildcard}")


def nat_acl_rules(topology: Topology) -> List[NatAclRule]:
    """NAT 用的 ACL 2000：只放通允许出网的源网段，其余隐含拒绝。"""
    if not topology.nat:
        return []
    rules: List[NatAclRule] = []
    seq = SEQ_STEP
    for zone_key in topology.nat.allowed_zones:
        zone = topology.zone(zone_key)
        rules.append(NatAclRule(
            seq=seq, action="permit",
            source_prefix=zone.prefix, source_wildcard=zone.wildcard,
            zone_key=zone_key,
        ))
        seq += SEQ_STEP
    return rules


def find_dead_rules(rules: Sequence[AccessRule]) -> List[AccessRule]:
    """给定一组已排序规则，找出其中被前面规则覆盖的死规则。"""
    kept: List[AccessRule] = []
    dead: List[AccessRule] = []
    for rule in rules:
        if any(rule_covers(k, rule) for k in kept):
            dead.append(rule)
        else:
            kept.append(rule)
    return dead
