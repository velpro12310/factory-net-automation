"""可达性推导引擎 —— 本工程的核心。

给定「源主机 + 目的主机 + 服务（协议/端口）」，推出一条流在网络里能不能通、
在哪一跳被拦、命中了哪条策略。整个推导不依赖任何真实设备或模拟器，
纯靠拓扑数据算出来——所以它能进 CI，也能在**改配置之前**先做一次预演。

推导顺序与真实转发的优先级保持一致：

    一、同域 → 二层交换，不受域间策略约束
        1.1 同一台接入交换机 → 直达
        1.2 跨接入交换机     → 两侧上行 Trunk 都必须放行该 VLAN
    二、跨域 → 三层转发
        2.1 源侧二层到网关（接入交换机上行 Trunk 放行该 VLAN）
        2.2 网关就绪（VRRP 主备在核心上都有 SVI 与 VRRP 实例）
        2.3 域间策略（首条命中生效；无命中即隐式默认拒绝）
        2.4 目的侧可达（内部域要求核心有该网段路由；互联网要求 NAT 放通该源域）

为什么把「策略」放在「目的侧可达」之前：排障时人最关心的是
「这条业务流为什么被拦」，策略命中信息比底层链路细节更有诊断价值。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .model import Host, Topology

VERDICT_PERMIT = "permit"
VERDICT_DENY = "deny"


# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class FlowResult:
    src: str
    dst: str
    service: str
    protocol: str
    port: Optional[int]
    from_zone: str
    to_zone: str
    verdict: str
    reason: str
    path: Tuple[str, ...] = ()
    steps: Tuple[str, ...] = ()
    policy_id: Optional[int] = None
    nat_applied: bool = False
    layer: str = "l3"

    @property
    def permitted(self) -> bool:
        return self.verdict == VERDICT_PERMIT

    @property
    def key(self) -> str:
        return f"{self.src}->{self.dst}:{self.service}"

    @property
    def is_cross_zone(self) -> bool:
        return self.from_zone != self.to_zone

    def as_dict(self) -> dict:
        return {
            "src": self.src, "dst": self.dst, "service": self.service,
            "protocol": self.protocol, "port": self.port,
            "from_zone": self.from_zone, "to_zone": self.to_zone,
            "verdict": self.verdict, "reason": self.reason,
            "policy_id": self.policy_id, "nat_applied": self.nat_applied,
            "layer": self.layer, "path": list(self.path),
        }


@dataclass(frozen=True)
class Violation:
    """期望与实测的偏差。"""

    kind: str                 # expectation | invariant
    id: str
    detail: str
    src: str = ""
    dst: str = ""
    service: str = ""
    expect: str = ""
    actual: str = ""
    reason: str = ""

    def as_dict(self) -> dict:
        return {
            "kind": self.kind, "id": self.id, "detail": self.detail,
            "src": self.src, "dst": self.dst, "service": self.service,
            "expect": self.expect, "actual": self.actual, "reason": self.reason,
        }


# --------------------------------------------------------------------------- #
class ReachabilityEngine:
    """基于拓扑数据的可达性推导。无状态，可对任意拓扑副本复用。"""

    def __init__(self, topology: Topology) -> None:
        self.topo = topology

    # ------------------------------------------------------------------ #
    # 对外
    # ------------------------------------------------------------------ #
    def check(self, src: str, dst: str, service: str) -> FlowResult:
        svc = self.topo.service(service)
        return self.check_flow(src, dst, svc.name, svc.protocol, svc.port)

    def check_flow(self, src: str, dst: str, service_name: str,
                   protocol: str, port: Optional[int]) -> FlowResult:
        src_host = self.topo.host(src)
        dst_host = self.topo.host(dst)
        ctx = _Ctx(src=src_host, dst=dst_host, service=service_name,
                   protocol=protocol, port=port,
                   from_zone=src_host.zone, to_zone=dst_host.zone)
        return self._decide(ctx)

    def internal_hosts(self) -> List[Host]:
        return [h for h in self.topo.hosts.values() if h.is_internal]

    def matrix(self, services: Optional[Sequence[str]] = None) -> List[FlowResult]:
        """全量矩阵：所有内部主机 × 所有主机 × 所有服务。

        内网主机作为源；互联网主机只作为目的（它们不会主动发起对本厂的访问）。
        """
        service_names = list(services) if services else list(self.topo.services)
        results: List[FlowResult] = []
        for src in self.internal_hosts():
            for dst in self.topo.hosts.values():
                if src.name == dst.name:
                    continue
                for name in service_names:
                    results.append(self.check(src.name, dst.name, name))
        return results

    @staticmethod
    def index(results: Iterable[FlowResult]) -> Dict[Tuple[str, str, str], FlowResult]:
        return {(r.src, r.dst, r.service): r for r in results}

    def matrix_summary(self, results: Sequence[FlowResult]) -> dict:
        total = len(results)
        permitted = sum(1 for r in results if r.permitted)
        cross = [r for r in results if r.is_cross_zone]
        cross_permitted = sum(1 for r in cross if r.permitted)
        by_pair: Dict[str, Dict[str, int]] = {}
        for r in results:
            pair = f"{r.from_zone}->{r.to_zone}"
            bucket = by_pair.setdefault(pair, {"permit": 0, "deny": 0})
            bucket[r.verdict] += 1
        return {
            "total": total,
            "permitted": permitted,
            "denied": total - permitted,
            "permit_rate": round(permitted / total, 4) if total else 0.0,
            "cross_zone_total": len(cross),
            "cross_zone_permitted": cross_permitted,
            "zone_matrix": by_pair,
        }

    # ------------------------------------------------------------------ #
    # 内部推导
    # ------------------------------------------------------------------ #
    def _decide(self, ctx: "_Ctx") -> FlowResult:
        if ctx.from_zone == ctx.to_zone:
            return self._intra_zone(ctx)
        return self._cross_zone(ctx)

    # -- 同域：二层 ----------------------------------------------------- #
    def _intra_zone(self, ctx: "_Ctx") -> FlowResult:
        zone = self.topo.zone(ctx.from_zone)
        steps: List[str] = [f"同域（{zone.name}）：二层交换，受 VLAN 与 Trunk 约束"]

        if ctx.from_zone == "internet":
            return self._deny(ctx, "互联网主机不作为内网访问源", steps, layer="l2")

        if ctx.src.attached_to == ctx.dst.attached_to:
            steps.append(f"同接在 {ctx.src.attached_to}，VLAN {zone.vlan} 内直达")
            return self._permit(ctx, "同交换机二层直达", steps, layer="l2")

        ok, why = self._l2_uplink(ctx.src.attached_to or "", zone.vlan)
        steps.append(f"源侧上行：{why}")
        if not ok:
            return self._deny(ctx, f"源侧二层不通：{why}", steps, layer="l2")

        ok, why = self._l2_uplink(ctx.dst.attached_to or "", zone.vlan)
        steps.append(f"目的侧上行：{why}")
        if not ok:
            return self._deny(ctx, f"目的侧二层不通：{why}", steps, layer="l2")

        return self._permit(ctx, f"VLAN {zone.vlan} 内二层可达", steps, layer="l2")

    # -- 跨域：三层 ----------------------------------------------------- #
    def _cross_zone(self, ctx: "_Ctx") -> FlowResult:
        zone_from = self.topo.zone(ctx.from_zone)
        zone_to = self.topo.zone(ctx.to_zone)
        steps: List[str] = [
            f"跨域：{zone_from.name} → {zone_to.name}",
        ]

        if ctx.from_zone == "internet":
            return self._deny(ctx, "互联网主机不作为内网访问源", steps)

        # 2.1 源侧二层到网关
        ok, why = self._l2_uplink(ctx.src.attached_to or "", zone_from.vlan)
        steps.append(f"源侧到网关：{why}")
        if not ok:
            return self._deny(ctx, f"源侧二层不通：{why}", steps)

        # 2.2 网关就绪
        ok, why = self._gateway_ready(ctx.from_zone)
        steps.append(f"网关状态：{why}")
        if not ok:
            return self._deny(ctx, f"网关不可用：{why}", steps)

        # 2.3 域间策略
        policy = self.topo.resolve_policy(ctx.from_zone, ctx.to_zone,
                                          ctx.protocol, ctx.port)
        if policy is None:
            steps.append("域间策略：无匹配规则")
            return self._deny(ctx, "无匹配策略，落到隐式默认拒绝", steps)
        steps.append(f"域间策略：命中规则 {policy.id}（{policy.action}）— {policy.desc}")
        if policy.action != "permit":
            return self._deny(
                ctx, f"被策略 {policy.id} 拒绝：{policy.desc}", steps,
                policy_id=policy.id,
            )

        # 2.4 目的侧可达
        nat_applied = False
        if ctx.to_zone == "internet":
            nat = self.topo.nat
            if nat is None or not nat.enabled:
                steps.append("NAT：未启用")
                return self._deny(ctx, "出口未启用 NAT，内网流量无法出网", steps,
                                  policy_id=policy.id)
            if not nat.allows_zone(ctx.from_zone):
                steps.append(f"NAT：{zone_from.name} 不在允许出网的区域列表中")
                return self._deny(
                    ctx,
                    f"{zone_from.name} 未纳入 NAT 出口策略（允许区域："
                    f"{'、'.join(nat.allowed_zones)}）",
                    steps, policy_id=policy.id,
                )
            nat_applied = True
            steps.append(f"NAT：经 {nat.device}:{nat.public_interface} 做源地址转换（{nat.mode}）")
        else:
            if not any(core.svi_for(zone_to.vlan) for core in self.topo.cores()):
                steps.append(f"核心缺少 VLAN {zone_to.vlan} 的 SVI")
                return self._deny(
                    ctx, f"核心交换机上没有 {zone_to.name} 的网关 SVI，无路由可达",
                    steps, policy_id=policy.id,
                )
            ok, why = self._l2_uplink(ctx.dst.attached_to or "", zone_to.vlan)
            steps.append(f"目的侧二层：{why}")
            if not ok:
                return self._deny(ctx, f"目的侧二层不通：{why}", steps,
                                  policy_id=policy.id)

        path = self._path(ctx, nat_applied)
        return FlowResult(
            src=ctx.src.name, dst=ctx.dst.name, service=ctx.service,
            protocol=ctx.protocol, port=ctx.port,
            from_zone=ctx.from_zone, to_zone=ctx.to_zone,
            verdict=VERDICT_PERMIT,
            reason=f"策略 {policy.id} 放通" + ("，且经 NAT 出网" if nat_applied else ""),
            path=tuple(path), steps=tuple(steps),
            policy_id=policy.id, nat_applied=nat_applied, layer="l3",
        )

    # ------------------------------------------------------------------ #
    def _l2_uplink(self, device_name: str, vlan: Optional[int]) -> Tuple[bool, str]:
        """接入交换机能否把该 VLAN 送上核心。"""
        if vlan is None:
            return False, "该域没有对应 VLAN"
        device = self.topo.devices.get(device_name)
        if device is None:
            return False, f"设备 {device_name} 不存在"
        if not device.has_vlan(vlan):
            return False, f"{device_name} 未定义 VLAN {vlan}"

        for trunk in device.trunks():
            if not trunk.allows_vlan(vlan):
                continue
            peer = self.topo.devices.get(trunk.peer_device)
            if peer is None:
                continue
            back = peer.iface(trunk.peer_port)
            if back is not None and back.allows_vlan(vlan):
                return True, f"{device_name}:{trunk.name} → {peer.name}:{back.name}（放行 VLAN {vlan}）"
        return False, f"{device_name} 没有放行 VLAN {vlan} 的上行 Trunk"

    def _gateway_ready(self, zone_key: str) -> Tuple[bool, str]:
        """判断该域的网关是否可用。

        判定口径是**业务连续性**：只要主备中任意一台核心具备该 VLAN 的 SVI，
        备份接管后业务就不会中断，因此判为可用。
        「主设备缺 SVI」这类配置下发不完整的问题由拓扑结构自检负责报出
        （见 model.Topology.structural_issues）——业务影响与配置正确性必须分开判，
        否则会出现「网络其实是通的，工具却报不可达」的误报。
        """
        zone = self.topo.zone(zone_key)
        if zone.vlan is None or zone.gateway is None:
            return False, f"安全域 {zone_key} 未定义 VLAN 或网关"

        group = self.topo.vrrp_for_vlan(zone.vlan)
        candidates: List[Tuple[str, object]] = []
        if group:
            for role in ("master", "backup"):
                name = group.get(role)
                device = self.topo.devices.get(name) if name else None
                if device is not None and device.svi_for(zone.vlan) is not None:
                    candidates.append((role, device))
        else:
            candidates = [(c.name, c) for c in self.topo.cores()
                          if c.svi_for(zone.vlan) is not None]

        if not candidates:
            return False, (f"没有任何核心设备具备 VLAN {zone.vlan} 的 SVI，"
                           f"网关 {zone.gateway} 不可用")

        note = "，".join(f"{role}={device.name}" for role, device in candidates)
        return True, f"网关 {zone.gateway} 可用（{note}）"

    def _path(self, ctx: "_Ctx", nat_applied: bool) -> List[str]:
        path = [ctx.src.name, ctx.src.attached_to or "?"]
        if ctx.to_zone == "internet":
            path.append("核心交换机")
            if nat_applied and self.topo.nat:
                path.append(self.topo.nat.device)
        else:
            path.append("核心交换机")
            path.append(ctx.dst.attached_to or "?")
        path.append(ctx.dst.name)
        return path

    # ------------------------------------------------------------------ #
    @staticmethod
    def _permit(ctx: "_Ctx", reason: str, steps: Sequence[str], layer: str = "l3") -> FlowResult:
        return FlowResult(
            src=ctx.src.name, dst=ctx.dst.name, service=ctx.service,
            protocol=ctx.protocol, port=ctx.port,
            from_zone=ctx.from_zone, to_zone=ctx.to_zone,
            verdict=VERDICT_PERMIT, reason=reason,
            path=tuple([ctx.src.name, ctx.src.attached_to or "?", ctx.dst.attached_to or "?", ctx.dst.name]),
            steps=tuple(steps), layer=layer,
        )

    @staticmethod
    def _deny(ctx: "_Ctx", reason: str, steps: Sequence[str],
              policy_id: Optional[int] = None, layer: str = "l3") -> FlowResult:
        return FlowResult(
            src=ctx.src.name, dst=ctx.dst.name, service=ctx.service,
            protocol=ctx.protocol, port=ctx.port,
            from_zone=ctx.from_zone, to_zone=ctx.to_zone,
            verdict=VERDICT_DENY, reason=reason,
            path=tuple(), steps=tuple(steps), policy_id=policy_id, layer=layer,
        )


@dataclass
class _Ctx:
    src: Host
    dst: Host
    service: str
    protocol: str
    port: Optional[int]
    from_zone: str
    to_zone: str


# --------------------------------------------------------------------------- #
# 期望与不变式校验
# --------------------------------------------------------------------------- #
def check_expectations(engine: ReachabilityEngine,
                       expectations: Sequence[dict]) -> List[Violation]:
    """逐条核对声明式的期望（关键业务流）。"""
    violations: List[Violation] = []
    for item in expectations:
        result = engine.check(item["src"], item["dst"], item["service"])
        expect = item["expect"]
        if result.verdict != expect:
            violations.append(Violation(
                kind="expectation",
                id=item.get("id", f"{item['src']}->{item['dst']}:{item['service']}"),
                detail=item.get("note", ""),
                src=item["src"], dst=item["dst"], service=item["service"],
                expect=expect, actual=result.verdict, reason=result.reason,
            ))
    return violations


def check_invariants(engine: ReachabilityEngine,
                     invariants: Sequence[dict],
                     services: Optional[Sequence[str]] = None) -> List[Violation]:
    """核对不变式：按域对**自行构造**流量组合并全量扫描。

    这里刻意不复用 ``engine.matrix()``——那个矩阵只以内部主机为源
    （互联网主机不会主动发起对本厂的访问）。但「外部网络不得进入内网」
    这类不变式的源恰恰是互联网主机，复用会导致「零组合匹配」的假通过。
    """
    all_services = list(services) if services else list(engine.topo.services)
    all_hosts = list(engine.topo.hosts.values())
    violations: List[Violation] = []

    for rule in invariants:
        from_zone = rule.get("from_zone")
        to_zone = rule.get("to_zone")
        service_filter = rule.get("service")
        expect = rule["expect"]

        if not service_filter or service_filter == "all":
            service_names = all_services
        else:
            service_names = [service_filter]

        src_hosts = [h for h in all_hosts if not from_zone or h.zone == from_zone]
        dst_hosts = [h for h in all_hosts if not to_zone or h.zone == to_zone]

        matched = 0
        for src in src_hosts:
            for dst in dst_hosts:
                if src.name == dst.name:
                    continue
                for name in service_names:
                    result = engine.check(src.name, dst.name, name)
                    matched += 1
                    if result.verdict != expect:
                        violations.append(Violation(
                            kind="invariant", id=rule["id"],
                            detail=rule.get("note", ""),
                            src=result.src, dst=result.dst, service=result.service,
                            expect=expect, actual=result.verdict, reason=result.reason,
                        ))

        if matched == 0:
            violations.append(Violation(
                kind="invariant", id=rule["id"],
                detail=(f"不变式未匹配到任何流量组合——安全域或服务名可能写错："
                        f"from={from_zone} to={to_zone} service={service_filter}"),
                expect=expect, actual="no-match",
            ))

    return violations
