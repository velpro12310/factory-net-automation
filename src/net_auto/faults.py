"""故障注入：把拓扑改坏，验证检查套件能否检出。

两个用途，第二个比第一个更重要：

  1. **网络变更回归验证**：任何配置改动（加策略、改 VLAN、调路由）先在本工具里
     跑一遍，看它会破坏哪些既有要求——在真机上试错的成本是停产。
  2. **证明检查套件不是摆设**：故意注入一个已知缺陷，要求检查套件必须报错。
     如果注入后检查照样全绿，说明检查有盲区。这与测试领域的变异测试同源，
     也和前两个项目里「并发超卖缺陷注入」是同一个思路。

注意：注入分两类，检出路径也不同。
  * **行为类**（漏放行 VLAN、误删 ACL、关掉 NAT）→ 由可达性矩阵与期望检查检出
  * **数据类**（接入口 VLAN 划错、VLAN 未定义）→ 由拓扑结构自检检出
两类都必须覆盖，只测行为类会漏掉「配置本身写错但暂时没影响」的隐患。
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Dict, List, Optional

from .acl import DEFAULT_DENY_POLICY_ID
from .generator import GenerationError, generate_configs
from .model import Device, Interface, SecurityPolicy, Svi, Topology, VlanDef
from .reachability import (
    ReachabilityEngine,
    Violation,
    check_expectations,
    check_invariants,
)


class MutationError(Exception):
    """注入参数有问题（设备/接口不存在等）。"""


# --------------------------------------------------------------------------- #
# 变异算子
# --------------------------------------------------------------------------- #
def _mutate_interface(topology: Topology, device_name: str, port: str,
                      **changes) -> Interface:
    device = topology.device(device_name)
    for index, iface in enumerate(device.interfaces):
        if iface.name == port:
            updated = replace(iface, **changes)
            device.interfaces[index] = updated
            return updated
    raise MutationError(f"{device_name} 上不存在接口 {port}")


def _remove_vlan_from_all_trunks(topology: Topology, params: Dict) -> None:
    """把某台设备（含对端）所有 Trunk 上的指定 VLAN 全部摘掉。

    这是「VLAN 未放行」的真实故障形态：只摘一端会被另一条冗余链路兜住，
    只有整台设备的上行都不放行才会真正断网。这一点本身也说明
    「双上联 + VRRP」的设计是有意义的。
    """
    device = topology.device(params["device"])
    vlan = int(params["vlan"])
    touched = 0
    for trunk in list(device.trunks()):
        if vlan not in trunk.allow_vlans:
            continue
        _mutate_interface(topology, device.name, trunk.name,
                          allow_vlans=tuple(v for v in trunk.allow_vlans if v != vlan))
        peer_name, _, peer_port = trunk.peer.partition(":")
        if peer_name in topology.devices:
            peer = topology.devices[peer_name].iface(peer_port)
            if peer is not None and vlan in peer.allow_vlans:
                _mutate_interface(topology, peer_name, peer_port,
                                  allow_vlans=tuple(v for v in peer.allow_vlans if v != vlan))
        touched += 1
    if touched == 0:
        raise MutationError(f"{device.name} 上没有任何 Trunk 放行 VLAN {vlan}")


def _delete_policy(topology: Topology, params: Dict) -> None:
    policy_id = int(params["id"])
    before = len(topology.policies)
    topology.policies = [p for p in topology.policies if p.id != policy_id]
    if len(topology.policies) == before:
        raise MutationError(f"策略 {policy_id} 不存在")


def _insert_catchall_permit(topology: Topology, params: Dict) -> None:
    """在最前面插入一条 any -> any permit。

    这是最危险的一类误操作：管理员为了「临时放开某条业务」图省事写了 any any permit，
    结果把全部隔离要求一次性破坏掉。可达性矩阵会成片报错。
    """
    topology.policies = sorted(
        topology.policies + [SecurityPolicy(
            id=int(params.get("id", 5)), from_zone="any", to_zone="any",
            action="permit", protocol="any", ports=None,
            desc="注入：临时放通（any -> any permit）",
        )],
        key=lambda p: p.id,
    )


def _remove_svi(topology: Topology, params: Dict) -> None:
    """删除某台（或全部核心）设备上某个 VLAN 的 SVI。

    ``all_cores=True`` 时删除所有核心上的该 SVI —— 这是会造成**业务真中断**的形态；
    只删一台核心属于「配置下发不完整」（备份可接管），由结构自检检出。
    两种形态对应不同的验证目标，故意都保留。
    """
    vlan = int(params["vlan"])
    if params.get("all_cores"):
        targets = [d.name for d in topology.cores()]
    else:
        targets = [params["device"]]

    removed = 0
    for name in targets:
        device = topology.device(name)
        if device.svi_for(vlan) is None:
            continue
        device.svis = [s for s in device.svis if s.vlan != vlan]
        device.vrrp = [v for v in device.vrrp if v.vlan != vlan]
        removed += 1
    if removed == 0:
        raise MutationError(f"目标设备 {targets} 上都没有 VLAN {vlan} 的 SVI")


def _change_svi_ip(topology: Topology, params: Dict) -> None:
    device = topology.device(params["device"])
    vlan = int(params["vlan"])
    for index, svi in enumerate(device.svis):
        if svi.vlan == vlan:
            device.svis[index] = Svi(vlan=vlan, ip=params["ip"])
            return
    raise MutationError(f"{device.name} 上没有 VLAN {vlan} 的 SVI")


def _disable_nat(topology: Topology, params: Dict) -> None:
    if topology.nat is None:
        raise MutationError("拓扑未定义 NAT 配置")
    topology.nat = replace(topology.nat, enabled=False)


def _misassign_access_port(topology: Topology, params: Dict) -> None:
    """把接入口划到错误的 VLAN —— 典型的数据类配置错误。

    这类错误不会让网络立刻断（可达性引擎按「域 -> VLAN」映射推导，
    不看端口的实际 VLAN），但设备上这台主机会被划进别的广播域，
    是真实的现场故障根源，所以必须由结构自检兜住。
    """
    _mutate_interface(topology, params["device"], params["port"],
                      vlan=int(params["vlan"]))


def _remove_vlan_definition(topology: Topology, params: Dict) -> None:
    vlan = int(params["vlan"])
    if vlan not in topology.vlans:
        raise MutationError(f"VLAN {vlan} 未定义，无需删除")
    del topology.vlans[vlan]


def _remove_static_route(topology: Topology, params: Dict) -> None:
    device = topology.device(params["device"])
    dest = params["dest"]
    before = len(device.static_routes)
    device.static_routes = [r for r in device.static_routes if r.dest != dest]
    if len(device.static_routes) == before:
        raise MutationError(f"{device.name} 上没有去往 {dest} 的静态路由")


def _remove_vlan_from_trunk_port(topology: Topology, params: Dict) -> None:
    """只摘掉**某一个**上行口上的 VLAN，另一条上行仍然放行。

    用于验证冗余设计的有效性：单条链路故障不应导致业务中断。
    这类注入的期望是「不被业务可用性检查检出」——注入后依然全绿，
    才说明双上联 + VRRP 真的起到了作用。
    """
    device = topology.device(params["device"])
    iface = device.iface(params["port"])
    if iface is None:
        raise MutationError(f"{params['device']} 上不存在接口 {params['port']}")
    vlan = int(params["vlan"])
    if vlan not in iface.allow_vlans:
        raise MutationError(f"{params['device']}:{params['port']} 上的 Trunk 未放行 VLAN {vlan}")
    _mutate_interface(topology, params["device"], params["port"],
                      allow_vlans=tuple(v for v in iface.allow_vlans if v != vlan))


MUTATIONS = {
    "remove_vlan_from_trunk_port": _remove_vlan_from_trunk_port,
    "remove_vlan_from_all_trunks": _remove_vlan_from_all_trunks,
    "delete_policy": _delete_policy,
    "insert_catchall_permit": _insert_catchall_permit,
    "remove_svi": _remove_svi,
    "change_svi_ip": _change_svi_ip,
    "disable_nat": _disable_nat,
    "misassign_access_port": _misassign_access_port,
    "remove_vlan_definition": _remove_vlan_definition,
    "remove_static_route": _remove_static_route,
}


# --------------------------------------------------------------------------- #
@dataclass
class FaultResult:
    fault_id: str
    name: str
    mutation: str
    expect_detected: bool
    expect_symptom: str
    detected: bool
    passed: bool                       # 是否与 expect_detected 相符
    structural_issues: List[str]
    expectation_violations: List[Violation]
    invariant_violations: List[Violation]
    generation_rejected: bool
    symptom: str

    @property
    def stray_failure_count(self) -> int:
        return len(self.expectation_violations) + len(self.invariant_violations)

    def as_dict(self) -> dict:
        return {
            "fault_id": self.fault_id, "name": self.name, "mutation": self.mutation,
            "expect_detected": self.expect_detected, "detected": self.detected,
            "passed": self.passed,
            "structural_issues": len(self.structural_issues),
            "expectation_violations": len(self.expectation_violations),
            "invariant_violations": len(self.invariant_violations),
            "generation_rejected": self.generation_rejected,
            "symptom": self.symptom,
        }


def apply_mutation(topology: Topology, mutation: str, params: Dict) -> Topology:
    """在**副本**上注入故障，原始拓扑保持不变。"""
    if mutation not in MUTATIONS:
        raise MutationError(f"未知的变异算子 {mutation}，可选：{sorted(MUTATIONS)}")
    clone = topology.clone()
    MUTATIONS[mutation](clone, params or {})
    return clone


def run_fault(topology: Topology, fault: Dict, expectations: Dict) -> FaultResult:
    """注入单个故障并跑完整检查套件。"""
    mutated = apply_mutation(topology, fault["mutation"], fault.get("params", {}))

    structural = mutated.structural_issues()

    generation_rejected = False
    try:
        generate_configs(mutated, "fault-injection")
    except GenerationError:
        generation_rejected = True

    engine = ReachabilityEngine(mutated)
    exp_violations = check_expectations(engine, expectations.get("expectations", []))
    inv_violations = check_invariants(engine, expectations.get("invariants", []))

    detected = bool(structural or exp_violations or inv_violations or generation_rejected)

    symptom = "未检出任何异常"
    if structural:
        symptom = f"结构自检报错：{structural[0]}"
    elif exp_violations:
        v = exp_violations[0]
        symptom = f"期望失效：{v.id} {v.src}->{v.dst}:{v.service} 期望 {v.expect} 实际 {v.actual}"
    elif inv_violations:
        v = inv_violations[0]
        symptom = (f"不变式失效：{v.id} {v.src}->{v.dst}:{v.service} "
                   f"期望 {v.expect} 实际 {v.actual}")
    elif generation_rejected:
        symptom = "配置生成被拒绝（拓扑自检未通过）"

    expect_detected = bool(fault.get("expect_detected", True))
    return FaultResult(
        fault_id=fault["id"],
        name=fault.get("name", ""),
        mutation=fault["mutation"],
        expect_detected=expect_detected,
        expect_symptom=fault.get("expect_symptom", ""),
        detected=detected,
        passed=(detected == expect_detected),
        structural_issues=list(structural),
        expectation_violations=list(exp_violations),
        invariant_violations=list(inv_violations),
        generation_rejected=generation_rejected,
        symptom=symptom,
    )


def run_all_faults(topology: Topology, faults: List[Dict], expectations: Dict) -> List[FaultResult]:
    return [run_fault(topology, fault, expectations) for fault in faults]
