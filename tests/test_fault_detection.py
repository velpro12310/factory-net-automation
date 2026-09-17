"""故障检出能力测试（6 条，TC-FLT-001 ~ 006）。

本组是整个工程可信度的**背书**：把拓扑故意改坏，要求校验套件必须报错。
如果哪天有人把校验改松了（比如删掉了某条不变式、或把全矩阵扫描换成抽样），
这里会立刻失败。

与前两个项目里的「并发超卖缺陷注入」是同一个思路：不只验证系统正确，
还要验证**验证手段本身有效**（等价于测试领域的变异测试）。
"""

from __future__ import annotations

import pytest

from net_auto.traceability import case

pytestmark = pytest.mark.fault


def result_of(fault_results, fault_id: str):
    matches = [r for r in fault_results if r.fault_id == fault_id]
    assert matches, f"未找到故障 {fault_id} 的注入结果"
    return matches[0]


def assert_all_faults_pass(fault_results) -> None:
    mismatched = [r for r in fault_results if not r.passed]
    assert not mismatched, (
        "以下注入故障的检出结果与期望不符："
        + "；".join(f"{r.fault_id}(期望检出={r.expect_detected} 实际={r.detected})"
                    for r in mismatched)
    )


# --------------------------------------------------------------------------- #
@case("TC-FLT-001", "REQ-FLT-011", priority="P0")
def test_vlan_not_allowed_is_detected(fault_results):
    assert_all_faults_pass(fault_results)
    r = result_of(fault_results, "FLT-001")

    assert r.detected, "漏放行 VLAN 必须被检出"
    assert r.expectation_violations, "应体现为关键业务流期望失效"
    assert len(r.expectation_violations) >= 5, (
        f"服务器区不可达应影响多条业务流，实际只有 {len(r.expectation_violations)} 条"
    )
    assert "二层" in r.symptom or "Trunk" in r.symptom or "deny" in r.symptom


@case("TC-FLT-002", "REQ-FLT-012", priority="P0")
def test_deleted_permit_policy_is_detected(fault_results):
    r = result_of(fault_results, "FLT-002")

    assert r.detected, "误删放通策略必须被检出"
    assert len(r.expectation_violations) >= 4, (
        f"删除车间到服务器的策略应影响多条业务流，实际 {len(r.expectation_violations)} 条"
    )
    kinds = {v.service for v in r.expectation_violations}
    assert "MES-WEB" in kinds, f"应包含 MES 业务流，实际受影响服务 {kinds}"


@case("TC-FLT-003", "REQ-FLT-013", priority="P0")
def test_over_permissive_rule_is_detected(fault_results):
    r = result_of(fault_results, "FLT-003")

    assert r.detected, "过度放通必须被检出"
    assert len(r.invariant_violations) >= 600, (
        f"any->any permit 会成片破坏隔离要求，实际只检出 {len(r.invariant_violations)} 处——"
        f"说明不变式扫描的覆盖面不足"
    )
    # 同时应有期望失效（隔离类期望也被打破）
    assert r.expectation_violations, "隔离类期望也应失效"


@case("TC-FLT-004", "REQ-FLT-014", priority="P0")
def test_missing_gateway_svi_is_detected(fault_results):
    r = result_of(fault_results, "FLT-004")

    assert r.detected, "网关 SVI 缺失必须被检出"
    assert r.generation_rejected, "拓扑自检不通过时应拒绝生成配置"
    assert r.structural_issues, "应给出结构级报错"
    assert any("SVI" in issue for issue in r.structural_issues), (
        f"报错信息应指明 SVI 缺失：{r.structural_issues}"
    )


@case("TC-FLT-005", "REQ-FLT-015", priority="P0")
def test_disabled_nat_is_detected(fault_results):
    r = result_of(fault_results, "FLT-005")

    assert r.detected, "NAT 失效必须被检出"
    assert len(r.expectation_violations) >= 2, (
        f"办公区与服务器区出网都应失效，实际 {len(r.expectation_violations)} 条"
    )
    assert any("NAT" in v.reason for v in r.expectation_violations), (
        "失效原因应指向 NAT"
    )


@case("TC-FLT-006", "REQ-FLT-016", priority="P0")
def test_data_level_error_is_detected(fault_results):
    """接入口 VLAN 划错属于数据类错误——可达性检查发现不了，必须靠结构自检。"""
    r = result_of(fault_results, "FLT-006")

    assert r.detected, "数据类配置错误必须被检出"
    assert r.structural_issues, "应给出结构级报错"
    assert not r.expectation_violations, (
        "这类错误短期内不影响可达性推导——正因为如此，只做行为检查会漏掉它"
    )
    assert any("VLAN" in issue for issue in r.structural_issues)
