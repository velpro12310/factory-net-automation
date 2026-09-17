"""用例、需求、校验能力三者的追溯元数据。

比一般的功能测试多一层：**校验能力覆盖率**。
功能测试只关心「需求有没有被用例覆盖」，网络校验还要回答
「这台工具具备哪些校验能力、每项能力有没有被用例真正触发过」。

举例：这个工程能查拓扑连线不对称、能查 ACL 死规则、能查 NAT 一致性——
如果某条能力写了代码却没有任何用例覆盖它，那它随时可能静默失效。
把能力列成清单并由用例声明引用，覆盖率就把这种「僵尸校验」暴露出来了。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import FunctionType
from typing import Any, Callable, Dict, List, Optional, Set

import yaml


@dataclass
class RequirementMeta:
    id: str
    title: str
    module: str = ""
    description: str = ""
    source: str = ""


@dataclass
class CheckItem:
    """一项校验能力。key 形如 ``CHK-MATRIX``。"""

    key: str
    name: str
    module: str = ""
    description: str = ""
    detects: str = ""


@dataclass
class CaseMeta:
    id: str
    title: str
    category: str = ""
    module: str = ""
    requirement: str = ""
    checks: List[str] = field(default_factory=list)
    method: str = ""            # 用例设计方法
    kind: str = "正向"          # 正向 / 负向 / 变异
    priority: str = "P1"
    expected: str = ""
    automated: bool = True

    @property
    def primary_check(self) -> str:
        return self.checks[0] if self.checks else ""


# --------------------------------------------------------------------------- #
def _load(path: str) -> Dict[str, Any]:
    return yaml.safe_load(open(path, "r", encoding="utf-8")) or {}


def load_requirements(path: str) -> Dict[str, RequirementMeta]:
    out: Dict[str, RequirementMeta] = {}
    for item in _load(path).get("requirements", []):
        out[item["id"]] = RequirementMeta(
            id=item["id"], title=item.get("title", ""), module=item.get("module", ""),
            description=item.get("description", ""), source=item.get("source", ""),
        )
    return out


def load_checks(path: str) -> List[CheckItem]:
    out: List[CheckItem] = []
    for item in _load(path).get("checks", []):
        out.append(CheckItem(
            key=item["key"], name=item.get("name", ""), module=item.get("module", ""),
            description=item.get("description", ""), detects=item.get("detects", ""),
        ))
    return out


def load_cases(path: str) -> Dict[str, CaseMeta]:
    out: Dict[str, CaseMeta] = {}
    for item in _load(path).get("cases", []):
        checks = item.get("checks") or []
        if isinstance(checks, str):
            checks = [checks]
        out[item["id"]] = CaseMeta(
            id=item["id"], title=item.get("title", ""),
            category=item.get("category", ""), module=item.get("module", ""),
            requirement=item.get("requirement", ""), checks=[str(c) for c in checks],
            method=item.get("method", ""), kind=item.get("kind", "正向"),
            priority=item.get("priority", "P1"), expected=item.get("expected", ""),
            automated=bool(item.get("automated", True)),
        )
    return out


def case(case_id: str, requirement: str, priority: str = "P1"):
    """把用例编号与需求编号挂到测试函数上，供 pytest 钩子与报告读取。"""

    def decorator(fn: FunctionType) -> FunctionType:
        fn._case_id = case_id              # type: ignore[attr-defined]
        fn._requirement = requirement      # type: ignore[attr-defined]
        fn._priority = priority            # type: ignore[attr-defined]
        return fn

    return decorator


# --------------------------------------------------------------------------- #
def audit_traceability(
    requirements: Dict[str, RequirementMeta],
    cases: Dict[str, CaseMeta],
    results: Dict[str, dict],
) -> Dict[str, Any]:
    case_reqs = {c.requirement for c in cases.values() if c.requirement}
    return {
        "requirements_total": len(requirements),
        "requirements_covered": len(set(requirements) & case_reqs),
        "cases_total": len(cases),
        "cases_executed": len(set(cases) & set(results)),
        "uncovered_requirements": sorted(set(requirements) - case_reqs),
        "dangling_requirement_refs": sorted(case_reqs - set(requirements)),
        "cases_not_executed": sorted(set(cases) - set(results)),
        "results_without_case_meta": sorted(set(results) - set(cases)),
        "coverage_rate": round(len(set(requirements) & case_reqs) / len(requirements), 4)
        if requirements else 0.0,
    }


def build_matrix(
    requirements: Dict[str, RequirementMeta],
    cases: Dict[str, CaseMeta],
    results: Dict[str, dict],
) -> List[dict]:
    by_req: Dict[str, List[str]] = {}
    for meta in cases.values():
        if meta.requirement:
            by_req.setdefault(meta.requirement, []).append(meta.id)

    rows: List[dict] = []
    for req_id, req in requirements.items():
        case_ids = sorted(by_req.get(req_id, []))
        statuses = [results.get(cid, {}).get("status", "not_run") for cid in case_ids]
        if not case_ids:
            status = "未覆盖"
        elif "failed" in statuses:
            status = "失败"
        elif "not_run" in statuses:
            status = "部分执行"
        else:
            status = "通过"
        rows.append({
            "requirement": req_id, "requirement_title": req.title,
            "module": req.module, "cases": case_ids, "case_count": len(case_ids),
            "status": status, "source": req.source,
        })
    return rows


def check_coverage(
    checks: List[CheckItem],
    cases: Dict[str, CaseMeta],
    results: Dict[str, dict],
) -> Dict[str, Any]:
    """校验能力覆盖清单：每项能力被哪些用例触发、结果如何。"""
    covered: Dict[str, List[str]] = {}
    for meta in cases.values():
        for key in meta.checks:
            covered.setdefault(key, []).append(meta.id)

    rows: List[dict] = []
    for check in checks:
        case_ids = sorted(covered.get(check.key, []))
        statuses = [results.get(cid, {}).get("status", "not_run") for cid in case_ids]
        if not case_ids:
            status = "未覆盖"
        elif "failed" in statuses:
            status = "失败"
        elif "not_run" in statuses:
            status = "部分执行"
        else:
            status = "通过"
        kinds: Dict[str, int] = {}
        for cid in case_ids:
            kind = cases[cid].kind
            kinds[kind] = kinds.get(kind, 0) + 1
        rows.append({
            "check": check.key, "name": check.name, "module": check.module,
            "description": check.description, "detects": check.detects,
            "cases": case_ids, "case_count": len(case_ids), "kinds": kinds,
            "status": status,
        })

    total = len(checks)
    covered_count = sum(1 for r in rows if r["case_count"] > 0)
    return {
        "total": total,
        "covered": covered_count,
        "rate": round(covered_count / total, 4) if total else 0.0,
        "uncovered": [r["check"] for r in rows if r["case_count"] == 0],
        "rows": rows,
    }
