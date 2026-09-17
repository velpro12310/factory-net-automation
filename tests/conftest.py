"""pytest 夹具与用例追溯钩子。

夹具策略：整个会话只加载一次拓扑、只生成一次配置、只跑一次全量矩阵与故障注入，
结果在用例之间共享。原因不只是快——更重要的是**保证所有用例看的是同一份数据**：
如果每个用例各自加载拓扑，一旦文件被改动，不同用例会基于不同版本判断，
失败信息会互相矛盾，排查时先怀疑人生。

`GENERATED_AT` 固定成一个常量，是为了让「生成幂等性」这条用例可判定：
如果生成器引入时间戳以外的不确定量，这条用例会立刻失败。
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Dict, Iterator

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for path in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from net_auto.acl import all_canonical_acls  # noqa: E402
from net_auto.faults import run_all_faults  # noqa: E402
from net_auto.generator import config_stats, generate_configs, write_configs  # noqa: E402
from net_auto.loader import (  # noqa: E402
    load_expectations,
    load_faults,
    load_topology,
    topology_summary,
)
from net_auto.reachability import (  # noqa: E402
    ReachabilityEngine,
    check_expectations,
    check_invariants,
)
from net_auto.validator import check_all_configs  # noqa: E402

ARTIFACT_DIR = PROJECT_ROOT / "artifacts"
REPORT_DIR = PROJECT_ROOT / "reports"
CASES_DIR = PROJECT_ROOT / "cases"

#: 固定生成时间：让「生成幂等」可判定，同时让报告里的时间戳稳定
GENERATED_AT = "2026-09-11 10:00:00"


# --------------------------------------------------------------------------- #
# 会话级夹具
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="session")
def topology():
    """严格模式加载：结构自检不通过就直接失败，避免在不干净的数据上跑用例。"""
    return load_topology()


@pytest.fixture(scope="session")
def expectations() -> Dict:
    return load_expectations()


@pytest.fixture(scope="session")
def fault_defs():
    return load_faults()


@pytest.fixture(scope="session")
def engine(topology) -> ReachabilityEngine:
    return ReachabilityEngine(topology)


@pytest.fixture(scope="session")
def configs(topology) -> Dict[str, str]:
    return generate_configs(topology, GENERATED_AT)


@pytest.fixture(scope="session")
def config_issues(topology, configs) -> Dict[str, list]:
    """配置回读比对结果：{设备名: [问题]}，全一致时为空字典。"""
    return check_all_configs(topology, configs)


@pytest.fixture(scope="session")
def acls(topology):
    return all_canonical_acls(topology)


@pytest.fixture(scope="session")
def fault_results(topology, fault_defs, expectations):
    return run_all_faults(topology, fault_defs, expectations)


@pytest.fixture(scope="session")
def matrix(engine):
    return engine.matrix()


@pytest.fixture(scope="session")
def matrix_summary(engine, matrix) -> Dict:
    return engine.matrix_summary(matrix)


@pytest.fixture(scope="session")
def generated_files(topology, configs) -> Iterator[list]:
    """把配置真正写盘（文档用例要验证产物）。"""
    yield write_configs(configs)


# --------------------------------------------------------------------------- #
# 用例追溯
# --------------------------------------------------------------------------- #
RESULTS: Dict[str, dict] = {}


def _case_id_of(item: pytest.Item):
    fn = getattr(item, "function", None)
    case_id = getattr(fn, "_case_id", None) if fn is not None else None
    callspec = getattr(item, "callspec", None)
    if callspec is not None and "case_id" in callspec.params:
        case_id = callspec.params["case_id"]
    return case_id


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call):
    outcome = yield
    report = outcome.get_result()

    case_id = _case_id_of(item)
    if not case_id:
        return

    fn = getattr(item, "function", None)
    requirement = getattr(fn, "_requirement", "") if fn is not None else ""
    try:
        report.user_properties.append(("用例编号", case_id))
        if requirement:
            report.user_properties.append(("关联需求", requirement))
    except Exception:
        pass

    entry = RESULTS.setdefault(case_id, {"status": "not_run"})

    if report.when == "setup" and report.failed:
        entry.update(status="failed", phase="setup", nodeid=item.nodeid,
                     error=str(report.longrepr)[:900])
    elif report.when == "call":
        if report.failed:
            entry.update(status="failed", phase="call", nodeid=item.nodeid,
                         duration=round(report.duration, 4),
                         error=str(report.longrepr)[:900])
        elif entry.get("status") != "failed":
            entry.update(status="passed", phase="call", nodeid=item.nodeid,
                         duration=round(report.duration, 4))
    elif report.when == "teardown" and report.failed and entry.get("status") == "passed":
        entry.update(status="failed", phase="teardown",
                     error=str(report.longrepr)[:900])


# --------------------------------------------------------------------------- #
def _build_state() -> Dict:
    """把领域侧的量化结果落盘，供报告使用。

    刻意在 sessionfinish 里独立算一遍，而不是复用夹具：
    sessionfinish 阶段夹具已销毁，且报告要能在「只跑部分用例」时照常生成。
    """
    topology = load_topology()
    expectations = load_expectations()
    faults = load_faults()

    configs = generate_configs(topology, GENERATED_AT)
    engine = ReachabilityEngine(topology)
    matrix = engine.matrix()

    exp_violations = check_expectations(engine, expectations.get("expectations", []))
    inv_violations = check_invariants(engine, expectations.get("invariants", []))
    fault_results = run_all_faults(topology, faults, expectations)
    config_issues = check_all_configs(topology, configs)

    dead_rules = []
    for zone_key, acl in all_canonical_acls(topology).items():
        for rule in acl.dropped:
            dead_rules.append({
                "acl": acl.acl_number,
                "rule": f"policy {rule.policy_id} {rule.action} {rule.protocol}",
                "reason": f"被同 ACL 中更宽的规则覆盖（源域 {zone_key}）",
            })

    audit_extra = []
    structural = topology.structural_issues()
    if structural:
        audit_extra.append(f"拓扑结构自检问题 {len(structural)} 条")
    if config_issues:
        audit_extra.append(f"配置回读不一致设备 {len(config_issues)} 台")
    if exp_violations:
        audit_extra.append(f"期望偏差 {len(exp_violations)} 条")
    if inv_violations:
        audit_extra.append(f"不变式偏差 {len(inv_violations)} 条")

    matrix_summary = engine.matrix_summary(matrix)
    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "topology": topology_summary(topology),
        "matrix": matrix_summary,
        "expectations": {
            "total": len(expectations.get("expectations", [])),
            "violations": [v.as_dict() for v in exp_violations],
        },
        "invariants": {
            "total": len(expectations.get("invariants", [])),
            "violations": [v.as_dict() for v in inv_violations],
        },
        "faults": [r.as_dict() for r in fault_results],
        "configs": config_stats(configs),
        "config_issues": config_issues,
        "dead_rules": dead_rules,
        "structural_issues": structural,
        "audit_extra": audit_extra,
    }


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    results_payload = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "exit_status": int(exitstatus),
        "case_count": len(RESULTS),
        "passed": sum(1 for r in RESULTS.values() if r.get("status") == "passed"),
        "failed": sum(1 for r in RESULTS.values() if r.get("status") == "failed"),
        "results": RESULTS,
    }
    (ARTIFACT_DIR / "results.json").write_text(
        json.dumps(results_payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    try:
        state = _build_state()
    except Exception as exc:                      # noqa: BLE001
        state = {"error": f"领域状态采集失败：{exc}"}
    (ARTIFACT_DIR / "topology_state.json").write_text(
        json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8"
    )
