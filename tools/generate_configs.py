"""生成设备配置并按需写盘。

用法::

    python tools/generate_configs.py                  # 生成 + 自检 + 写盘
    python tools/generate_configs.py --check-only     # 只校验不写盘（变更预演）
    python tools/generate_configs.py --matrix-csv     # 额外导出可达性矩阵 CSV
    python tools/generate_configs.py --force          # 跳过结构自检强制生成（仅调试用）

**变更预演**是日常最有用的用法：改完拓扑先 `--check-only`，
确认结构自检与可达性校验都过，再考虑下发。
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "src"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from net_auto.acl import all_canonical_acls  # noqa: E402
from net_auto.generator import (  # noqa: E402
    GenerationError,
    config_stats,
    generate_configs,
    write_configs,
)
from net_auto.loader import (  # noqa: E402
    load_expectations,
    load_topology,
    topology_summary,
)
from net_auto.reachability import (  # noqa: E402
    ReachabilityEngine,
    check_expectations,
    check_invariants,
)
from net_auto.validator import check_all_configs, parse_config  # noqa: E402

OUTPUT_DIR = ROOT / "output"


def export_matrix_csv(engine: ReachabilityEngine, path: Path) -> Path:
    """导出全量可达性矩阵为 CSV，便于用 Excel 透视或与历史版本做 diff。"""
    rows = engine.matrix()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["源主机", "源域", "目的主机", "目的域", "服务",
                         "协议", "端口", "结论", "层级", "命中策略", "经NAT", "原因"])
        for r in rows:
            writer.writerow([
                r.src, r.from_zone, r.dst, r.to_zone, r.service,
                r.protocol, r.port if r.port is not None else "",
                "permit" if r.permitted else "deny", r.layer,
                r.policy_id if r.policy_id is not None else "",
                "是" if r.nat_applied else "", r.reason,
            ])
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="智能工厂网络配置生成与预演校验")
    parser.add_argument("--topology", default=None, help="拓扑文件路径（默认 topology/smart_factory.yaml）")
    parser.add_argument("--out", default=None, help="输出目录（默认 output/configs）")
    parser.add_argument("--check-only", action="store_true", help="只校验不写盘")
    parser.add_argument("--matrix-csv", action="store_true", help="导出可达性矩阵 CSV")
    parser.add_argument("--force", action="store_true", help="跳过拓扑自检强制生成")
    parser.add_argument("--no-timestamp", action="store_true", help="配置头部使用固定时间戳（便于比对）")
    args = parser.parse_args()

    topology = load_topology(args.topology, strict=False)
    summary = topology_summary(topology)

    print("=" * 78)
    print(f"  {summary['name']}（{summary['site']}）  {summary['version']}")
    print("=" * 78)
    print(f"  安全域 {summary['zones']} ｜ VLAN {summary['vlans']} ｜ 网络设备 {summary['devices']}"
          f" ｜ 端系统 {summary['hosts']}（外部 {summary['external_hosts']}）")
    print(f"  服务类型 {summary['services']} ｜ 安全策略 {summary['policies']}"
          f" ｜ 链路 {summary['links']} ｜ VRRP 组 {summary['vrrp_groups']}")

    # ---- 1. 结构自检 ----
    issues = topology.structural_issues()
    print(f"\n[1/4] 拓扑结构自检 …… {'通过' if not issues else f'{len(issues)} 个问题'}")
    for issue in issues:
        print(f"      ✗ {issue}")
    if issues and not args.force:
        print("\n结构自检未通过，已终止。请修复 topology/smart_factory.yaml 后重试。")
        return 1

    # ---- 2. 生成配置 ----
    timestamp = "2026-09-11 10:00:00" if args.no_timestamp else time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        configs = generate_configs(topology, timestamp, force=args.force)
    except GenerationError as exc:
        print(f"\n[2/4] 配置生成 …… 失败\n{exc}")
        return 1

    stats = config_stats(configs)
    print(f"\n[2/4] 配置生成 …… 完成：{stats['devices']} 台设备 / "
          f"{stats['lines']} 行 / {stats['bytes']} 字节")
    for name, lines in stats["per_device"].items():
        print(f"      · {name:<14} {lines:>4} 行")

    # ---- 3. 配置回读一致性 ----
    config_issues = check_all_configs(topology, configs)
    print(f"\n[3/4] 配置回读一致性 …… {'通过' if not config_issues else f'{len(config_issues)} 台不一致'}")
    for name, items in config_issues.items():
        for item in items:
            print(f"      ✗ {name}: {item}")

    # ---- 4. 可达性校验 ----
    expectations = load_expectations()
    engine = ReachabilityEngine(topology)
    exp_violations = check_expectations(engine, expectations.get("expectations", []))
    inv_violations = check_invariants(engine, expectations.get("invariants", []))
    matrix_summary = engine.matrix_summary(engine.matrix())

    print(f"\n[4/4] 可达性校验")
    print(f"      全量矩阵 {matrix_summary['total']} 个组合："
          f"放通 {matrix_summary['permitted']} / 阻断 {matrix_summary['denied']}")
    print(f"      关键业务流期望 {len(expectations.get('expectations', []))} 条 "
          f"-> 偏差 {len(exp_violations)}")
    for v in exp_violations[:10]:
        print(f"        ✗ {v.id} {v.src}->{v.dst}:{v.service} "
              f"期望 {v.expect} 实际 {v.actual}（{v.reason}）")
    print(f"      隔离不变式 {len(expectations.get('invariants', []))} 条 "
          f"-> 偏差 {len(inv_violations)}")
    for v in inv_violations[:10]:
        print(f"        ✗ {v.id} {v.src}->{v.dst}:{v.service} "
              f"期望 {v.expect} 实际 {v.actual}")

    dead = []
    for zone_key, acl in all_canonical_acls(topology).items():
        for rule in acl.dropped:
            dead.append(f"{zone_key}: policy {rule.policy_id} {rule.action}")
    if dead:
        print(f"      ACL 死规则 {len(dead)} 条（已剔除，不影响功能但会误导排障）：")
        for item in dead:
            print(f"        · {item}")

    all_clean = not issues and not config_issues and not exp_violations and not inv_violations

    # ---- 写盘 ----
    if not args.check_only:
        # write_configs 会在给定目录下再建 configs 子目录，所以这里只传根输出目录
        target_root = Path(args.out) if args.out else OUTPUT_DIR
        print(f"\n[写盘] 配置输出到 {target_root / 'configs'}")
        for path in write_configs(configs, target_root):
            print(f"      · {path.relative_to(ROOT)}")

        if args.matrix_csv:
            csv_path = export_matrix_csv(engine, target_root / "reachability_matrix.csv")
            print(f"[写盘] 可达性矩阵 CSV：{csv_path.relative_to(ROOT)}")
    else:
        print("\n[预演] --check-only：未写盘")

    print("\n" + "=" * 78)
    print("  结论：" + ("全部校验通过，可以进入下发流程" if all_clean else "存在问题，禁止下发"))
    print("=" * 78)
    return 0 if all_clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
