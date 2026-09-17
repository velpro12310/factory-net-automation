"""可达性矩阵与期望测试（4 条，TC-MTX-001 ~ 004）。

这一组是整套校验的「面」：逐条期望只能覆盖关键业务流，
隔离要求必须靠全矩阵扫描才能真正兜住。
"""

from __future__ import annotations

import pytest

from net_auto.reachability import VERDICT_DENY, VERDICT_PERMIT
from net_auto.traceability import case

pytestmark = pytest.mark.matrix


@case("TC-MTX-001", "REQ-MTX-011", priority="P0")
def test_full_matrix_generated_with_definite_verdicts(topology, matrix):
    internal = [h for h in topology.hosts.values() if h.is_internal]
    expected_total = len(internal) * (len(topology.hosts) - 1) * len(topology.services)

    assert len(matrix) == expected_total, (
        f"矩阵应覆盖 {len(internal)} 源主机 × {len(topology.hosts) - 1} 目标主机 × "
        f"{len(topology.services)} 服务 = {expected_total} 个组合，实际 {len(matrix)}"
    )

    for result in matrix:
        assert result.verdict in (VERDICT_PERMIT, VERDICT_DENY), (
            f"{result.key} 结论未定义：{result.verdict}"
        )
        assert result.reason, f"{result.key} 缺少结论依据"
        if result.permitted:
            assert result.steps, f"{result.key} 放通结论缺少推导过程"
        else:
            assert result.steps, f"{result.key} 阻断结论缺少推导过程"

    # 组合键唯一，不存在重复或漏配
    keys = {r.key for r in matrix}
    assert len(keys) == len(matrix), "矩阵中存在重复组合"


@case("TC-MTX-002", "REQ-MTX-012", priority="P0")
def test_key_business_flows_expectations_hold(engine, expectations):
    items = expectations["expectations"]
    permitted = [i for i in items if i["expect"] == "permit"]
    denied = [i for i in items if i["expect"] == "deny"]
    assert len(items) >= 25, f"关键业务流期望不应少于 25 条，实际 {len(items)}"
    assert permitted and denied, "期望清单应同时包含放通与阻断两类"

    violations = []
    for item in items:
        result = engine.check(item["src"], item["dst"], item["service"])
        if result.verdict != item["expect"]:
            violations.append(
                f"{item['id']} {item['src']}->{item['dst']}:{item['service']} "
                f"期望 {item['expect']} 实际 {result.verdict}（{result.reason}）"
            )
    assert not violations, f"关键业务流期望偏差 {len(violations)} 条：\n  " + "\n  ".join(violations)


@case("TC-MTX-003", "REQ-MTX-013", priority="P0")
def test_isolation_invariants_hold_across_matrix(engine, expectations):
    from net_auto.reachability import check_invariants

    invariants = expectations["invariants"]
    assert len(invariants) >= 13, f"不变式不应少于 13 条，实际 {len(invariants)}"

    violations = check_invariants(engine, invariants)

    # 「零匹配」是假通过：说明不变式写错了域或服务名，必须单独识别出来
    no_match = [v for v in violations if v.actual == "no-match"]
    assert not no_match, (
        f"有 {len(no_match)} 条不变式未匹配到任何流量组合（可能安全域或服务名写错）："
        f"{[v.id for v in no_match]}"
    )

    real = [v for v in violations if v.actual != "no-match"]
    assert not real, (
        f"隔离要求被破坏 {len(real)} 处，例如 "
        f"{real[0].id} {real[0].src}->{real[0].dst}:{real[0].service} "
        f"期望 {real[0].expect} 实际 {real[0].actual}"
    )


@case("TC-MTX-004", "REQ-MTX-011", priority="P1")
def test_intra_zone_reachability_unaffected_by_policies(engine, matrix):
    same_zone = [r for r in matrix if not r.is_cross_zone and r.from_zone != "internet"]
    assert same_zone, "矩阵中应存在同域流量组合"

    blocked = [r for r in same_zone if not r.permitted]
    assert not blocked, (
        f"同域内流量不应被域间策略阻断，实际有 {len(blocked)} 条被拒，"
        f"例如 {blocked[0].key}（{blocked[0].reason}）"
    )
    assert all(r.layer == "l2" for r in same_zone), "同域流量应判定为二层转发"
    assert all(r.policy_id is None for r in same_zone), "同域流量不应命中域间策略"
