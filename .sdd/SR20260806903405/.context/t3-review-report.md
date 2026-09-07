# T3 语义 Review 合并报告与重验记录 · SR20260806903405

> 时间：2026-09-04
> Task：T3 客户端SDK与集成验证

## Review 报告（合并）

- Reviewer A（requirements/security/evolution）：**fail**，6 findings（F1 map 符号缺失、F2 HandleDeath 偏差决策、F3 DeleteClient 竞态、F4 Deleter 缺 Remove、F5 验收未闭环、F6 bundle.json 说法）
- Reviewer B（performance/structure/readability/evolution）：**fail**，7 findings（F1 so 缺 auth_event.cpp、F2 map 未登记、F3 bundle.json、F4 会话复活竞态、F5 死存储+缺 Remove、F6 日志缺上下文、F7 测试缺口）
- 原始报告：/tmp/opencode/review-t3-a.md、/tmp/opencode/review-t3-b.md

## 主 Agent 裁决与修复

| # | 来源 | 裁决 | 处置 |
|---|---|---|---|
| B-F1 | libsg_collect_sdk sources 缺 auth_event.cpp（so 内 AuthEvent 符号无法解析） | 成立 | 已修复：sources 追加 `src/auth_event.cpp`；`llvm-nm -D` 验证 so 动态表 0 个 undefined AuthEvent 符号 |
| A-F1/B-F2 | sg_collect_sdk.map 未导出 AuthEventSubscribeClient/AuthEvent 符号 | 成立 | 已修复：map 追加 5 方法 + Marshalling/ReadFromParcel/Unmarshalling + VTT/vtable 条目（写法对齐 EventSubscribeClient/SecurityEventFilter）；llvm-nm -D 验证全部导出（vtable 动态表状态与既有 SecurityEventFilter 一致） |
| A-F2 | HandleDeath 自动重连 vs 设计"不自动重建"冲突 | 裁决：保留自动重连 | 用户核心诉求"类似 event_subscribe_client.h"（自动重连是范式本体行为，SA 重启后订阅自动恢复）；设计修订至 v6（3.1/4.4 两处） |
| A-F3/B-F4 | DeleteClient 与在途 HandleDeath 会话复活竞态 | 成立 | 已修复：新增 `deleted_` 标志，DeleteClient/Deleter 锁内置位；HandleDeath 每轮重试前 + 重建写回前检查，置位则销毁新会话并退出 |
| A-F4/B-F5 | Deleter 缺 RemoveDeathRecipient + 死存储 | 成立 | 已修复：Deleter 补 Remove（对齐范式 event_subscribe_client.cpp:55-57） |
| A-F5/B-F7 | SDK proxy 组包路径零覆盖、验收未闭环 | 成立（部分） | 已修复：补 ClientMethodsWithFakeClientId001（注入 clientId 走 proxy 失败路径）、ClientDeleter001（Deleter 兜底）、ClientSetDeathRecipient001（对齐范式用例）；端到端五接口经生成接口码到达服务端需真机 SA 3524 环境——登记 tasks-overview「待处理用例登记」（依赖真机，最终责任本 SR） |
| A-F6/B-F3 | bundle.json 未改 | 成立（不改为正确处置） | 裁决：维持不改。仓库 inner_kits 采用 header_files:[] + header_base 目录登记（event_subscribe_client.h 等既有头同模式，新头自动暴露）；逐一列举反而打破现状。设计第 5 节该条目修正（v6） |
| B-F6 | 重连失败日志缺 clientId 上下文 | 成立 | 已修复：ReCreatClient fail/recover fail 补 `%{private}s` clientId（隐私合规） |

## 重验

- 修复后执行 `hb build security_guard -t`：**build test success**
- `llvm-nm -D libsg_collect_sdk.z.so`：AuthEventSubscribeClient 5 方法 T 导出、AuthEvent 序列化 3 符号 T 导出、VTT 导出、undefined AuthEvent 符号 0 个
- deleted_ 竞态修复属控制流变更，已由双 Reviewer 给出合格判据（标志位 + 双检查点），未涉及公共契约，无需追加定向 Review
- 测试新增 3 用例（fake clientId proxy 路径 / Deleter 兜底 / SetDeathRecipient）
- open blocking findings：无（上机集成验证已登记待处理）
