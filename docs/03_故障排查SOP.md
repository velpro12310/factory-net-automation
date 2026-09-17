# 故障排查 SOP（标准作业程序）

本文件与 `topology/faults.yaml` 一一对应：每条注入故障都有对应章节，
`tests/test_docs.py::TC-DOC-002` 会自动检查覆盖度。
**改故障清单时必须同步改本文件**，否则 CI 会拦下。

---

## 〇、通用排查顺序

工厂网排障最忌「上来就改配置」。按下面的顺序走，能避免把一次故障变成两次：

1. **先看范围**：是个别主机不通，还是整区不通？
   - 个别主机 → 看接入口（VLAN、网线、端口 up/down）
   - 整区不通 → 看网关与上行 Trunk
2. **再看方向**：单向不通还是双向不通？
   - 单向不通 → 优先怀疑 ACL（ACL 是方向敏感的）
   - 双向不通 → 优先怀疑二层或路由
3. **最后看变化**：最近有没有改动？
   - 先回滚，再定位。**恢复业务优先于查明原因。**
4. 定位清楚后，**改 `topology/smart_factory.yaml` 重新生成配置**，
   不要直接登设备改——手工改动是配置漂移的根源。

### 常用定位命令

```
display vlan                          # VLAN 是否存在、哪些接口在 VLAN 内
display port vlan                     # 接口的 VLAN 归属
display interface brief               # 接口 up/down 与速率
display vrrp brief                    # VRRP 主备状态与虚拟地址
display ip routing-table              # 路由表（看有没有目的网段）
display acl all                       # ACL 全部规则与命中计数
display traffic-filter applied-record # 哪些接口应用了 ACL
display nat outbound                  # NAT 是否生效
display current-configuration | include route-static   # 静态路由
display logbuffer                     # 有没有 ACL 拒绝日志
```

> 关键技巧：`display acl all` 会显示每条规则的**命中计数**。
> 命中计数为 0 的放通规则，要么业务没跑到，要么它被前面的规则挡死了——这就是死规则。

---

## 一、FLT-001 接入交换机上行 Trunk 漏放行服务器 VLAN

**症状**：服务器区整区不可达。MES Web、数据库、OPC UA 全部访问失败，
但服务器本身的电源、系统都正常。

**影响面**：车间到 MES 的全部业务流中断，产线数据无法上报。

**定位步骤**：

1. 在核心交换机上执行 `display vlan 30`，确认 VLAN 30 存在且成员接口列表里
   **没有** 指向该接入交换机的上行口。
2. 在接入交换机上执行 `display port vlan`，核对两条上行 Trunk 的
   `Trunk VLAN List` 是否包含 30。
3. 用 `display interface brief` 确认接口物理状态正常（排除网线/光模块问题）。
4. 用本工具做一次快速定位：
   ```
   python tools/make_report.py --run -k FLT-001
   ```
   注入同名故障后，报告的「故障注入结果」会给出受影响的业务流清单。

**根因**：改 Trunk 配置时漏写了一个 VLAN。双上联设计下，两条上行都不放行才会真正断网，
所以这类错误往往在「调整链路」时被引入。

**处置步骤**：

1. 修改 `topology/smart_factory.yaml` 中对应 Trunk 的 `allow_vlans`，补上缺失的 VLAN。
2. 重新生成配置：`python tools/generate_configs.py`。
3. 下发前先跑可达性校验：`pytest -m "layer2 or matrix"`，确认服务器区业务流恢复放通。
4. 在维护窗口登录设备，用生成的配置片段修复 Trunk 放行列表。
5. 修复后执行 `display port vlan` 与 `display vlan 30` 复核。

**验证**：重跑 `pytest`，全部用例应通过；重点是 TC-L2-002/TC-L2-004 与 TC-MTX-002。

**预防**：Trunk 放行列表由拓扑文件生成，禁止手工增删 VLAN。

---

## 二、FLT-002 误删车间到 MES 的放通策略

**症状**：服务器区本身可达（能 ping 通网关），但车间 PLC 访问 MES 应用报连接超时。
`display acl all` 里看不到对应的 permit 规则。

**定位步骤**：

1. 在核心交换机上执行 `display acl 3010`，检查是否还有
   `rule permit tcp destination-port eq 8080` 这条规则。
2. 查看命中计数：如果 ACL 里最后一条 deny 的计数在快速上涨，说明流量被默认拒绝了。
3. 执行 `display logbuffer`，确认有 ACL 拒绝日志。
4. 用本工具核对：`pytest -k TC-ACL-001`，或直接比对
   `topology/smart_factory.yaml` 的 `security_policies` 与设备上的 `display acl 3010`。

**根因**：清理「冗余规则」时把仍在使用的放通规则一并删了。
这类误删往往发生在策略表整理或权限收紧的过程中。

**处置步骤**：

1. 在 `topology/smart_factory.yaml` 的 `security_policies` 中补回被删的策略
   （编号保持原值，避免打乱顺序语义）。
2. 重新生成配置并跑 `pytest -m security`，确认白名单端口全部恢复放通。
3. 在维护窗口把 ACL 补回设备。
4. 若无法立即定位到具体规则，**先回滚到上一版配置**（`output/configs` 里有备份），
   恢复业务后再做差异比对。

**验证**：`display acl 3010` 中相应规则存在；TC-ACL-001 与 TC-MTX-002 通过。

**预防**：策略表的每次改动都跑一次全量可达性校验，改动前先看报告里的
「可达性矩阵摘要」基线。

---

## 三、FLT-003 临时放通写成 any 到 any（catch-all permit）

**症状**：业务全部正常，甚至比原来更「通」了——这正是危险之处。
表现是隔离要求静默失效：办公终端能访问生产设备、生产网能出外网。

**定位步骤**：

1. 在核心交换机上 `display acl all`，检查是否存在
   `rule permit ip` 这类无源无目的的放通规则，且位置考前。
2. 核对规则顺序：catch-all permit 之前如果缺少针对各内网网段的 deny，
   后面的所有拒绝规则都会失效。
3. 用本工具全矩阵扫描定位：
   ```
   pytest -k TC-MTX-003
   ```
   注入该故障后，报告的「故障注入结果」会显示**成百条**隔离不变式失效——
   这正是「只抽查几条业务流发现不了」的典型例子。

**根因**：为了临时放开某条业务，图省事写了一条 `permit ip`，
事后忘记删除或收窄。

**处置步骤**：

1. 立即在 `security_policies` 中删除该 catch-all 放通规则。
2. 重新生成配置，并核对生成的 ACL 顺序满足：
   **具体放通 → 具体拒绝 → 出网放通 → 兜底拒绝**。
3. 跑 `pytest`，确认隔离不变式全部恢复。
4. 若确需临时放通，改为「源域 + 目的域 + 协议 + 端口」四要素齐全的精确规则，
   并在 `desc` 中写明有效期与责任人。

**验证**：`display acl all` 中不再有 catch-all permit；
TC-ACL-003/004/005 与 TC-MTX-003 全部通过。

**预防**：把「策略表中不得存在 from/to 为 any 的 permit 规则」写进校验
（本工程的 ACL 规范化阶段会检出并报告）。

---

## 四、FLT-004 核心交换机丢失服务器区网关 SVI

**症状**：分两种情况，必须区分对待。

- **业务表现**：主设备缺 SVI 时，备设备会接管 VRRP，业务**通常不受影响**。
- **配置表现**：结构自检报错「VRRP 组 30 的 master 设备 Core-SW-1 缺少 SVI」，
  且配置生成被拒绝。

**定位步骤**：

1. 在两台核心上执行 `display vrrp brief`，看 Master 列是否已经切换到 Core-SW-2。
2. 执行 `display interface Vlanif30`，确认哪台设备上该接口不存在。
3. 执行 `display ip routing-table`，确认服务器区网段是否仍能从核心学到。
4. 用本工具验证：
   ```
   pytest -k TC-L3-003
   ```
   注意区分两种注入：只删一台核心（业务仍通、结构自检报错）
   与两台核心都删（业务真中断）。

**根因**：配置下发不完整——批量脚本漏跑、或维护窗口中断。

**处置步骤**：

1. **优先确认业务是否真的中断**：若备设备已接管，属于配置不一致而非业务故障，
   可不占用紧急窗口修复。
2. 从 `output/configs/Core-SW-1.cfg` 提取对应的 `interface Vlanif30` 配置段。
3. 补齐 SVI 与 VRRP 配置，注意虚拟地址与优先级必须与拓扑一致。
4. 恢复后执行 `display vrrp brief` 确认主备状态与优先级符合设计（主 120 / 备 100）。
5. 若主设备需要抢占回主，确认 `preempt-mode timer delay` 已配置，避免震荡。

**验证**：`display interface Vlanif30` 两台设备都存在；结构自检无问题；TC-L3-004/005 通过。

**预防**：配置下发后立刻跑一次 `pytest -m "generation or topology"`，
结构自检能第一时间发现下发不完整。

---

## 五、FLT-005 出口路由器 NAT 未启用

**症状**：内网互访完全正常，但办公区与服务器区无法访问互联网，
系统补丁、时间同步、供应商云平台全部失败。

**定位步骤**：

1. 在出口路由器上执行 `display nat outbound`，确认公网口是否还有 `nat outbound 2000`。
2. 执行 `display acl 2000`，核对地址池是否包含办公区与服务器区网段，
   且顺序在隐含拒绝之前。
3. 检查公网口状态：`display interface GigabitEthernet0/0/3`。
4. 用本工具定位：
   ```
   pytest -k TC-FLT-005
   ```
   报告会列出因 NAT 失效而无法出网的业务流。

**根因**：更换出口设备或调整公网口时漏配 NAT；也可能被误删。

**处置步骤**：

1. **先确认 ACL 2000 存在**——`nat outbound` 引用不存在的 ACL 会直接报错，
   顺序不能颠倒。
2. 若 ACL 缺失，先按 `output/configs/RT-EGRESS.cfg` 补齐
   （只允许办公区与服务器区两个网段）。
3. 在公网口补回 `nat outbound 2000`。
4. 注意：**生产网与管理区绝不能加进 NAT 地址池**——这会违反
   「生产网不得出网」的合规要求，属于安全事件而不是可用性问题。

**验证**：`display nat outbound` 有输出；办公终端能访问外部地址；
TC-NAT-001/002 与 TC-MTX-002 通过。

**预防**：NAT 地址池与安全策略同源管理，改一处必须同时更新拓扑文件。

---

## 六、FLT-006 接入口 VLAN 划错

**症状**：**短期内可能看不出影响**。这是本类故障最危险的地方——
主机可能拿到错误网段的地址，或者被划进别的安全域却仍然「能上网」。

**定位步骤**：

1. 在接入交换机上执行 `display port vlan` 或 `display current-configuration interface`，
   逐口核对 VLAN 与台账是否一致。
2. 执行 `display mac-address`，看该端口下学到了哪些 MAC，
   判断是否有跨网段主机误接。
3. 用本工具做结构自检：
   ```
   pytest -k TC-TOPO-002
   ```
   结构自检会把「主机所属安全域」与「接入口实际 VLAN」逐条比对，直接指出不一致的端口。

**根因**：新装机或调整工位时接口划错 VLAN；或复制模板时未改 VLAN 号。

**处置步骤**：

1. 核对 `topology/smart_factory.yaml` 中该主机的 `zone` 与 `port` 定义，确认台账意图。
2. 若台账正确：修改设备端口 VLAN，`port default vlan <正确值>`。
3. 若台账本身就错：先修台账，再重新生成配置下发（**不要只改设备**）。
4. 修改后重新获取 IP（`ipconfig /renew` 或 `dhclient`），确认网段正确。

**验证**：TC-TOPO-002 与 TC-L2-006 通过；结构自检无问题。

**预防**：新装机一律先登记台账再下发端口配置；
结构自检纳入每次变更的必跑项——**行为类校验发现不了这类问题**。

---

## 七、变更前必跑回归清单

任何网络变更（加策略、改 VLAN、调路由、换设备）在**下发前**都应执行：

```bash
# 1) 结构自检 + 生成配置（结构不通过会直接拒绝生成）
python tools/generate_configs.py

# 2) 全量校验：配置一致性 + 可达性矩阵 + 期望 + 不变式 + 故障注入
pytest

# 3) 生成报告，重点看三处
python tools/make_report.py
#    · 可达性矩阵摘要   —— 与变更前基线比，放通/阻断数量是否有非预期变化
#    · 故障注入结果     —— 校验能力是否仍然有效
#    · 追溯一致性审计    —— 有没有需求/用例/校验能力的缺口
```

**判定标准**：报告的「可达性矩阵摘要」与变更前基线相比，
**放通组合数的变化必须有明确解释**。无法解释的变化一律视为风险，先查清再下发。
