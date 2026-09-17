@echo off
REM 一键跑通（Windows）：装依赖 -> 生成配置 -> 跑用例 -> 出报告
REM 用法：run.bat        或   run.bat -k fault
setlocal
cd /d "%~dp0"

set PY=%PYTHON%
if "%PY%"=="" set PY=python

echo 使用解释器：
%PY% --version
if errorlevel 1 (
  echo 未找到 python，请先安装 Python 3.10+ 并加入 PATH。
  exit /b 1
)

echo ==^> 安装依赖
%PY% -m pip install -q -r requirements.txt
if errorlevel 1 exit /b 1

echo ==^> 生成设备配置
%PY% tools\generate_configs.py
if errorlevel 1 (
  echo 配置生成失败：拓扑自检未通过，请先修复 topology/smart_factory.yaml
  exit /b 1
)

echo ==^> 执行用例并生成报告
%PY% tools\make_report.py --run %*

echo.
echo 配置产物：output\configs\*.cfg
echo 报告位置：reports\智能工厂网络_验收报告.html
endlocal
