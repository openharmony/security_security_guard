# T2 语义 Review 合并报告与重验记录 · SR20260806903405

> 时间：2026-09-03
> Task：T2 服务端会话管理与接入校验

## Review 报告（合并）

- Reviewer A（requirements/security/evolution）：**fail**，9 findings（R-1 Notify 缺长度守卫、R-2 uid 用例缺缝、R-3 SetAuthResult 权限零覆盖、R-4/R-5 契约形状偏差登记、S-1 clientId 保密假设偏弱、S-2 死亡通知失败不回滚、S-3 集合无上界、S-4 风险接受点、E-1 持锁调死亡通知）
- Reviewer B（performance/structure/readability/evolution）：**fail**，10 findings（PERF-1 持锁外部调用、PERF-2 单锁无注释、PERF-3 孤儿会话、EVO-1~4 测试缺口、READ-1 BUILD.gn 顺序、STRUCT-1~3 设计形状偏差）
- 原始报告：/tmp/opencode/review-t2-a.md、/tmp/opencode/review-t2-b.md

## 主 Agent 裁决与修复

| # | 来源 | 裁决 | 处置 |
|---|---|---|---|
| E-1/PERF-1 | Add/RemoveDeathRecipient 持锁执行 | 成立 | 已修复：三处全部移出锁外（锁内簿记/快照，锁外 binder 调用），头文件补锁纪律注释 |
| PERF-3/S-2 | AddDeathRecipient 失败不回滚 | 成立 | 已修复：失败 erase 会话返回 FAILED；deathRecipient_ 判空 |
| R-1 | NotifyAuthEvent 缺长度守卫 | 成立 | 已修复：入口加 MAX_AUTH_EVENT_STR_LEN 校验，超限记日志丢弃 |
| R-2/EVO-2 | uid 清单无测试缝，验收第 1 例缺 | 成立 | 已修复：uid 清单改为 manager 成员 allowedUids_ + IsUidAllowed()（#define private public 可注入）；补 DualTrackCheck002（native + getuid() 注入 → SUCCESS）与 IsUidAllowed001（空清单拒绝/补值生效） |
| EVO-1/R-3 | service.SetAuthResult 权限零覆盖 | 成立 | 已修复：补 SetAuthResultPermission001（HAP+DENIED→NO_PERMISSION）/002（HAP+GRANTED→SUCCESS 端到端含状态表断言） |
| EVO-4 | 死亡清理绕过 OnRemoteDied 链路 | 成立 | 已修复：SubscriberDied006 改经 deathRecipient_->OnRemoteDied(obj) 真实链路 |
| S-1 | clientId 保密假设偏弱 | 成立 | 已修复：会话操作（Subscribe/Unsubscribe/Destory）绑定 callerPid（不匹配 → BAD_PARAM），补 PidBound004 用例；clientId 日志全部转 %{private}s |
| S-3 | 集合无上界 | 成立 | 已修复：MAX_AUTH_EVENT_SUBSCRIBE_SIZE=1024（单会话 eventIds）/ MAX_AUTH_EVENT_RESULT_SIZE=1024（结果表），超限 FILTER_EXCEED_LIMIT（复用既有错误码）；补 CollectionSizeLimit001/002 |
| R-4/STRUCT-1/2/3 | 设计形状偏差未登记 | 成立 | 已处置：设计文档同步至 v5（路径 sa/、callerPid 参数化、GetAuthResult 预留读取口、uid 清单机制、权限常量 constexpr const char*、集合上限规格） |
| R-5/EVO-3 | "重复 clientId→BAD_PARAM" v4 后不可达 | 成立 | 已处置：保留内部防御分支，设计 §6 口径修正为"服务端生成保证唯一（内部防御）" |
| PERF-2 | 单锁无注释 | 成立 | 已修复：头文件补锁职责与纪律注释 |
| READ-1 | fuzz BUILD.gn 顺序 | 成立 | 已修复：统一字母序（callback_proxy 在前） |
| S-4 | SetAuthResult 不校验 eventId 归属；HAP 无系统应用判定 | 部分成立（设计行为） | 登记风险接受：结果表全局共享为设计行为（dev-design 4.6）；HAP 权限开放范围由 access_token 仓登记约束（存疑既有项）。后续如需收紧（eventId ∈ 订阅集合），由用户拍板 |
| R-5 补充 | — | — | — |

## 重验

- 修复后执行 `hb build security_guard -t`：**build test success**（全部 target 编译链接通过）
- 涉及锁序与回滚的修改（E-1/PERF-3）属控制流变更，但改动模式完全对齐既有 SetDeathCallBack 范式（锁内快照锁外执行 + 失败回滚），Reviewer A/B 在报告中已给出该范式的合格判据，无需追加定向 Review
- 测试新增 6 用例（DualTrackCheck002、SetAuthResultPermission001/002、PidBound004、CollectionSizeLimit001/002），死亡链路用例重写
- open blocking findings：无
