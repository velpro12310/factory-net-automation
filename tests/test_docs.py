"""文档与排查 SOP 测试（2 条，TC-DOC-001 ~ 002）。

把文档也纳入自动化校验：SOP 写漏一个故障场景、配置备份没生成，
和代码 bug 一样会让现场排障卡住。
文档只有被检查，才会被维护。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from net_auto.loader import PROJECT_ROOT, load_faults
from net_auto.traceability import case

pytestmark = pytest.mark.docs

SOP_PATH = PROJECT_ROOT / "docs" / "03_故障排查SOP.md"


@case("TC-DOC-001", "REQ-DOC-011", priority="P1")
def test_config_backups_generated(topology, configs, generated_files):
    assert len(generated_files) == len(topology.devices), (
        f"应为每台设备生成一份配置，实际 {len(generated_files)} 份"
    )

    out_dir = PROJECT_ROOT / "output" / "configs"
    for name, text in configs.items():
        path = out_dir / f"{name}.cfg"
        assert path.exists(), f"缺少配置文件 {path}"
        assert path.read_text(encoding="utf-8") == text, (
            f"{name}.cfg 内容与本次生成结果不一致（可能是上轮残留）"
        )

    # 文件名与设备名一一对应，不出现多余文件
    on_disk = {p.stem for p in out_dir.glob("*.cfg")}
    assert on_disk == set(topology.devices), (
        f"输出目录文件与设备清单不一致：多余 {on_disk - set(topology.devices)}，"
        f"缺少 {set(topology.devices) - on_disk}"
    )


@case("TC-DOC-002", "REQ-DOC-012", priority="P1")
def test_troubleshooting_sop_covers_all_faults():
    assert SOP_PATH.exists(), f"缺少故障排查 SOP：{SOP_PATH}"

    text = SOP_PATH.read_text(encoding="utf-8")
    faults = load_faults()
    assert faults, "故障清单为空，无法校验 SOP 覆盖度"

    missing = [f["id"] for f in faults if f["id"] not in text]
    assert not missing, f"SOP 未覆盖以下故障场景：{missing}"

    # 每个场景都要给出处置动作，不能只有标题
    for fault in faults:
        section_start = text.index(fault["id"])
        next_starts = [text.index(f["id"]) for f in faults if f["id"] != fault["id"]
                       and text.index(f["id"]) > section_start]
        section_end = min(next_starts) if next_starts else len(text)
        section = text[section_start:section_end]

        assert len(section) >= 200, f"{fault['id']} 的 SOP 内容过于简短"
        assert any(kw in section for kw in ("定位", "排查", "核对", "display", "检查")), (
            f"{fault['id']} 缺少具体排查动作"
        )
        assert any(kw in section for kw in ("处置", "修复", "恢复", "回滚")), (
            f"{fault['id']} 缺少处置步骤"
        )
