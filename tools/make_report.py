"""跑用例并生成 HTML / Excel 报告。

用法::

    python tools/make_report.py --run          # 先跑 pytest 再出报告（推荐）
    python tools/make_report.py                # 用上次的 artifacts 出报告
    python tools/make_report.py --run -k fault # 只跑故障检出用例并出报告

报告产物：
    reports/智能工厂网络_验收报告.html     最新报告（自包含）
    reports/智能工厂网络_验收报告.xlsx     多 Sheet 版本
    reports/history/...                    每次运行留档，便于对比变更前后
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "src"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from net_auto.report import (  # noqa: E402
    load_report_data,
    render_console_summary,
    write_excel,
    write_html,
)

CASES_DIR = ROOT / "cases"
ARTIFACT_DIR = ROOT / "artifacts"
REPORT_DIR = ROOT / "reports"


def run_pytest(extra_args: list[str]) -> int:
    cmd = [sys.executable, "-m", "pytest", "-q", *extra_args]
    print(f"执行： {' '.join(cmd)}\n")
    return subprocess.run(cmd, cwd=str(ROOT)).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="智能工厂网络验收报告生成器")
    parser.add_argument("--run", action="store_true", help="先执行 pytest")
    parser.add_argument("--no-history", action="store_true", help="不写入历史留档")
    args, extra = parser.parse_known_args()

    exit_code = 0
    if args.run:
        exit_code = run_pytest(extra)

    results_path = ARTIFACT_DIR / "results.json"
    if not results_path.exists():
        print(f"未找到 {results_path}，请先用 --run 执行一次 pytest。")
        return 1

    state_path = ARTIFACT_DIR / "topology_state.json"
    if not state_path.exists():
        print(f"警告：未找到 {state_path}，报告将缺少拓扑与矩阵数据。")

    data = load_report_data(
        str(CASES_DIR / "requirements.yaml"),
        str(CASES_DIR / "testcases.yaml"),
        str(CASES_DIR / "checks.yaml"),
        str(results_path),
        str(state_path) if state_path.exists() else None,
    )

    print()
    print(render_console_summary(data))
    print()

    html_path = write_html(data, str(REPORT_DIR / "智能工厂网络_验收报告.html"))
    print(f"HTML 报告：{html_path}")

    if not args.no_history:
        stamp = time.strftime("%Y%m%d_%H%M%S")
        history = REPORT_DIR / "history" / f"智能工厂网络_验收报告_{stamp}.html"
        write_html(data, str(history))
        print(f"历史留档：{history}")

    xlsx = write_excel(data, str(REPORT_DIR / "智能工厂网络_验收报告.xlsx"))
    print(f"Excel 报告：{xlsx}" if xlsx
          else "Excel 报告：跳过（未安装 openpyxl，pip install openpyxl 后可生成）")

    return exit_code if args.run else 0


if __name__ == "__main__":
    raise SystemExit(main())
