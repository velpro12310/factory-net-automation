#!/usr/bin/env bash
# 一键跑通：安装依赖 -> 生成配置 -> 执行 50 条用例 -> 生成 HTML/Excel 报告
# 用法：bash run.sh            或   bash run.sh -k fault
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python

echo "使用解释器：$($PY --version 2>&1)"
echo "==> 安装依赖"
"$PY" -m pip install -q -r requirements.txt

echo "==> 生成设备配置（结构自检不通过会直接拒绝）"
"$PY" tools/generate_configs.py

echo "==> 执行用例并生成报告"
"$PY" tools/make_report.py --run "$@"

echo
echo "配置产物：output/configs/*.cfg"
echo "报告位置：reports/智能工厂网络_验收报告.html"
