# 阻断服务使用者管理框架任务计划

## 元信息

- SR 编号：SR20260806903405
- AR 编号：无（dev 入口）
- 来源设计文档（唯一事实来源）：`.sdd/SR20260806903405/dev-design.md`（方案与契约变更章节为实现设计事实来源，验收标准章节为验证规格事实来源）
- 来源测试规格：`.sdd/SR20260806903405/dev-design.md` 第 6 节「验收标准」（轻量模式，无独立测试设计文档）
- 来源门禁结果：`.sdd/SR20260806903405/.context/dev-design-gate.md`
- 门禁结论：通过
- 任务总数：5（T4、T5 为工作流 done 后的增量迭代，按用户陆续补充的规格执行）
- 生成时间：2026-09-03（T4 追记：2026-09-07；T5 追记：2026-09-10）

## 执行规则

- `dev-design.md` 是实现设计与验证规格的唯一事实来源。开发每个任务前必须完整读取该文档，尤其是第 4 节「契约变更」与第 6 节「验收标准」。
- 按串行执行顺序逐个执行，编号与顺序一致；同一时刻只开发一个任务。
- T1-T3 为原计划任务（工作流已闭环）；T4 为 T3 交付后用户追加规格的增量迭代（HA 打点、整需求宏隔离、权限/配置校验、pending 重构、clientId 回迁客户端、超时处置）；T5 为 v9 设计变更增量迭代（移除服务端超时特性、会话关联重构为方案 D「会话即远端对象」、错误码场景全量梳理），随对话直接实施，不经过 task-split 重新拆分（单批次小步变更）。
- 设计文档发生变化时，停止开发，返回设计门禁并重新生成、确认任务计划。

## 串行执行顺序

```text
T1 → T2 → T3 → T4 → T5
```

## 任务计划

| 编号 | 任务 | 做什么 | 改哪些文件 | 验证哪些用例 | 前置 |
|---|---|---|---|---|---|
| T1 | 数据结构与IPC契约扩展 | 新增 AuthEvent parcelable、IAuthEventCallback 回调 broker；在 3524 的 IDL 追加 CreatAuthEventClient/DestoryAuthEventClient/SubscribeAuthEvent/UnsubscribeAuthEvent/SetAuthResult 五方法（clientId 会话范式 + 结果回填）并登记接口码 13-17，完成 IDL 构建接线，保证模块可编译 | `interfaces/inner_api/collect/include/auth_event.h`、`i_auth_event_callback.h`（新增）；`services/data_collect/idl/DataCollectManagerIdl.idl`、`interfaces/inner_api/collect/include/data_collect_manager_service_ipc_interface_code.h`（修改） | 验收：Parcelable 往返（AuthEvent 三字段含缺省值）；本任务内编译通过 | 无 |
| T2 | 服务端会话管理与接入校验 | 新增 AuthEventSubscribeManager（clientId 服务端生成回传、会话表、eventId 订阅集合、结果状态表 eventId→allowFlag、锁外分发、订阅者死亡清理、预留 NotifyAuthEvent 注入口、配额检查：进程≤2/设备≤16，复用 CLIENT_EXCEED_* 错误码）与 AuthEventCallbackProxy；在 DataCollectManagerService 上实现 5 个 IPC 方法，落地双轨校验（native token 查硬编码 uid 清单、HAP token 查 ohos.permission.kernel.AUTH_AUDIT_EVENT，CreatAuthEventClient 与 SetAuthResult 共用）；接入服务端 BUILD.gn 与单测 | `services/data_collect/sa/include/auth_event_subscribe_manager.h`、`services/data_collect/sa/src/auth_event_subscribe_manager.cpp`、`services/data_collect/sa/include/auth_event_callback_proxy.h`（新增）；`services/data_collect/sa/include/data_collect_manager_service.h`、`services/data_collect/sa/data_collect_manager_service.cpp`、`services/data_collect/BUILD.gn`、`test/unittest/data_collect/sa/auth_event_subscribe_manager_test.cpp`、`test/unittest/data_collect/BUILD.gn`（修改） | 验收：双轨校验 4 例；clientId 服务端生成非空唯一、伪造/空 id → BAD_PARAM；配额限制（同 pid 第 3 个 → PROCESS_LIMIT、满 16 → GLOBAL_LIMIT、销毁后可重建、重复 clientId → BAD_PARAM）；会话订阅（命中/未命中推送、退订、销毁后 Subscribe → BAD_PARAM、重复订阅幂等）；结果回填（状态表记录/覆盖、无会话 → BAD_PARAM）；死亡清理 | T1 |
| T3 | 客户端SDK与集成验证 | 新增 AuthEventSubscribeClient 会话客户端（静态 CreatClient/Subscribe/Unsubscribe/SetAuthResult/DeleteClient + 服务端回传的 clientId + Deleter + DeathRecipient，对齐 event_subscribe_client.h）与客户端回调适配（auth_event_callback_service 含 stub），编入 libsg_collect_sdk；登记 bundle.json inner_kits 新头文件；补 SDK 单测并完成整体编译与既有用例回归 | `interfaces/inner_api/collect/include/auth_event_subscribe_client.h`、`auth_event_callback_service.h`（新增）；`frameworks/common/collect/src/auth_event_subscribe_client.cpp`、`auth_event_callback_service.cpp`（新增）；`frameworks/common/collect/BUILD.gn`、`bundle.json`、`test/unittest/data_collect/BUILD.gn`（修改） | 验收：SDK 五接口经接口码 13-17 到达服务端、回调 function 被触发；整体编译产物含更新的 libsg_collect_service.z.so 与 libsg_collect_sdk.z.so；现有 data_collect 单测全部通过 | T2 |

计划表不保存阶段进度。`task-dev` 只在「执行记录」中写最终 `Completed` 或 `Blocked` 交接。

## 存疑汇总

任务计划确认前本节必须为空。若存在问题，使用下表记录并返回对应上游阶段处理。

| 编号 | 存疑项 | 涉及任务 | 需要确认的问题 | 回流阶段 |
|---|---|---|---|---|

（无——dev-design 存疑项不阻断任务边界：T2 以空 uid 清单占位，具体值由用户后续提供）

## 待处理用例登记

仅登记不影响当前任务主要完成状态的补充性验证；核心验证不得待处理。

| 用例编号 | 所在任务 | 依赖任务 | 当前无法执行原因 | 最终责任任务 | 状态 |
|---|---|---|---|---|---|
| 上机集成验证：SDK 五接口经 IDL 生成接口码端到端到达 SA 3524、服务端死亡重连恢复、AuthEvent 回调闭环 | T3 | T3 | 本机为 ARM 交叉编译环境，无真机 SA 3524 运行环境；单测已覆盖组包/回调/失败路径 | T3（本 SR 收尾） | Pending |

## 执行记录

由 `task-dev` 在每个任务完成或阻塞时追加一条记录；`task-split` 不预填。

### T1：数据结构与IPC契约扩展

- 状态：Completed
- 修改文件：新增 `interfaces/inner_api/collect/include/auth_event.h`、`interfaces/inner_api/collect/include/i_auth_event_callback.h`、`frameworks/common/collect/src/auth_event.cpp`、`test/unittest/data_collect/sa/auth_event_parcelable_test.cpp`；修改 `services/data_collect/idl/DataCollectManagerIdl.idl`、`interfaces/inner_api/collect/include/data_collect_manager_service_ipc_interface_code.h`、`services/data_collect/sa/include/data_collect_manager_service.h`、`services/data_collect/sa/data_collect_manager_service.cpp`、`test/unittest/data_collect/sa/data_collect_manager_service.h`、`services/data_collect/BUILD.gn`、`frameworks/common/collect/BUILD.gn`、`frameworks/common/collect/test/BUILD.gn`、`test/unittest/data_collect/BUILD.gn`、`test/unittest/inner_api/BUILD.gn`、19 个 `test/fuzztest/**/BUILD.gn`
- 核心实现：AuthEvent parcelable（eventId/content/metadata 手写序列化）；IAuthEventCallback broker（描述符 OHOS.Security.DataCollectManager.AuthEventCallback + CMD_ON_AUTH_EVENT）；IDL 追加 5 方法（CreatAuthEventClient [out] clientId 服务端生成、DestoryAuthEventClient、Subscribe/UnsubscribeAuthEvent、SetAuthResult）与 AuthEvent sequenceable；接口码登记 13-17（注释声明非 wire code，实际由 IDL 生成枚举分配 20-24）；服务类与 mock 头 5 个 override 占位实现（返回 FAILED，真实逻辑属 T2）；全量构建接线（24 处 target 补 auth_event.cpp 解决 IDL 重生成符号缺失）；Parcelable 往返单测 3 例（全字段/缺省值/空 parcel）
- 设计偏差：无（变更经用户确认后同步修订设计至 v4：clientId 改服务端生成）
- 待处理：无
- 后续须知：T2 须知——①修改真实服务头必须同步 mock 影子头 `test/unittest/data_collect/sa/data_collect_manager_service.h`；②SetAuthResult/NotifyAuthEvent 消费 content/metadata 时做长度上限校验（超限 BAD_PARAM）；③测试断言用 IDL 生成枚举 DataCollectManagerIdlIpcCode，禁止手写 SendRequest 13-17。uid 清单具体值仍待用户提供（空清单占位）
- 证据：AAW step 5 attempt 1；语义 Review 双 Reviewer pass（报告 `.context/t1-review-report.md`，7 findings 全部处置）；修复后 `hb build security_guard -t` 编译全绿；CodeCheck 经用户决策跳过

### T2：服务端会话管理与接入校验

- 状态：Completed
- 修改文件：新增 `services/data_collect/sa/include/auth_event_subscribe_manager.h`、`services/data_collect/sa/auth_event_subscribe_manager.cpp`、`services/data_collect/sa/include/auth_event_callback_proxy.h`、`services/data_collect/sa/auth_event_callback_proxy.cpp`、`test/unittest/data_collect/sa/auth_event_subscribe_manager_test.cpp`；修改 `services/data_collect/sa/data_collect_manager_service.cpp`（5 IPC 实现+双轨校验）、`services/data_collect/sa/include/data_collect_manager_service.h`、`test/unittest/data_collect/sa/data_collect_manager_service.h`（影子头同步）、`services/data_collect/BUILD.gn`、`test/unittest/data_collect/BUILD.gn`、9 个 `test/fuzztest/**/BUILD.gn`（补 manager/proxy cpp，字母序）
- 核心实现：AuthEventSubscribeManager 单例（会话表 clientId→{callback,pid,eventIds}、结果表 eventId→allowFlag、配额进程≤2/设备≤16、clientId 服务端生成"时间戳+原子计数器"、锁内快照锁外执行（死亡通知注册/注销/推送均在锁外）、AddDeathRecipient 失败回滚、NotifyAuthEvent 按 eventIds 命中分发+长度守卫）；双轨校验 IsCallerAllowedSubscribeAuthEvent（native→uid 白名单成员/HAP→VerifyAccessToken/其他→NO_PERMISSION，Creat 与 SetAuthResult 共用）；会话操作绑定 callerPid（跨进程持有效 id 操作 → BAD_PARAM）；集合上限 1024（FILTER_EXCEED_LIMIT）；单测 19 例（双轨 5 例含 uid 注入、SetAuthResult 权限 2 例端到端、配额 2 例、会话订阅/退订/幂等、pid 绑定、集合上限 2 例、死亡链路经真实 OnRemoteDied）
- 设计偏差：已同步设计至 v5——实现路径 sa/（非 sa/src/，对齐仓库惯例）；管理器方法带 callerPid 参数（pid 绑定）；GetAuthResult 为预留读取口（设计 1.2"预留读取口"落地）；uid 白名单改 manager 成员（原 initializer_list 常量）；SetAuthResult callerPid 用 pid_t；权限常量 constexpr const char*
- 待处理：无（uid 清单具体值仍待用户提供，空清单占位=暂拒 native token，IsUidAllowed001 已覆盖"补值即生效"语义）
- 后续须知：T3 须知——SDK 各方法（Subscribe/Unsubscribe/Destory/SetAuthResult）会携带服务端回传 clientId 调用，服务端按调用进程 pid 绑定校验，SDK 不跨进程共享 client 对象即可满足；clientId 日志已是 %{private}s，SDK 侧同样处理
- 证据：AAW step 6 attempt 1；语义 Review 双 Reviewer 初判 fail（19 findings），全部处置（必修 10 项已修复、登记 9 项），报告 `.context/t2-review-report.md`；修复后 `hb build security_guard -t` 编译全绿；CodeCheck 经用户决策跳过

### T3：客户端SDK与集成验证

- 状态：Completed
- 修改文件：新增 `interfaces/inner_api/collect/include/auth_event_callback_stub.h`、`auth_event_callback_service.h`、`auth_event_subscribe_client.h`；`frameworks/common/collect/src/auth_event_callback_stub.cpp`、`auth_event_callback_service.cpp`、`auth_event_subscribe_client.cpp`；`frameworks/common/collect/test/unittest/src/auth_event_sdk_test.cpp`；修改 `frameworks/common/collect/BUILD.gn`（SDK sources +auth_event.cpp +3 新源）、`frameworks/common/collect/sg_collect_sdk.map`（导出新类符号）、`frameworks/common/collect/test/BUILD.gn`（+4 源 +2 测试 +去重）
- 核心实现：AuthEventSubscribeClient 会话客户端（静态 CreatClient/Subscribe/Unsubscribe/SetAuthResult/DeleteClient + 服务端回传 clientId + Deleter 兜底 + DeathRecipient + HandleDeath 退避自动重连 {1,5,15,30,60×5} + deleted_ 竞态防护）；AuthEventCallbackService/Sturb 回调适配（双锁排空 + 接口 token/parcel 校验）；libsg_collect_sdk 编入 auth_event.cpp 并 map 导出全部对外符号（llvm-nm 验证）；SDK 单测 8 例（回调触发/stub 组包/坏 token/空 parcel/未知码/CreatClient 失败/幂等销毁/fake clientId proxy 路径/Deleter 兜底/SetDeathRecipient）
- 设计偏差：已同步设计至 v6——HandleDeath 自动重连（原 v5 写"不自动重建"，对齐 event_subscribe_client 范式后修订）；bundle.json 未修改（header_files 空数组 + header_base 目录登记，新头自动暴露，设计第 5 节原条目基于错误假设已修正）；SDK 测试落位 frameworks/common/collect/test（对齐 data_collect_kit_test 范式，非任务行原写的 test/unittest/data_collect）
- 待处理：无核心阻塞项；上机集成验证见「待处理用例登记」
- 后续须知：无（框架三任务已闭环；uid 清单补值与权限登记见设计存疑节）
- 证据：AAW step 7 attempt 1；语义 Review 双 Reviewer 初判 fail（13 findings），全部处置（必修 6 项已修复、裁决 2 项、登记 5 项），报告 `.context/t3-review-report.md`；修复后 `hb build security_guard -t` 编译全绿；llvm-nm 验证 so 符号完整（0 undefined AuthEvent）；CodeCheck 经用户决策跳过

### T4：增量迭代（HA 打点 + 宏隔离 + 校验增强 + 超时模型重构）

- 状态：Completed
- 修改文件：新增 `services/data_collect/sa/include/auth_event_reporter.h`、`services/data_collect/sa/auth_event_reporter.cpp`（HA 打点适配层，日志兜底 + ReportToHa 单点 TODO）；修改 `security_guard.gni`（开关 security_guard_auth_event_enable，默认 false）、`services/data_collect/idl/DataCollectManagerIdl.idl`（CreatAuthEventClient 改 [in] clientId + timeoutAllowFlag；SetAuthResult 增 clientId）、`interfaces/inner_api/collect/include/auth_event.h/.cpp`（+eventIndex 字段与序列化）、`data_collect_manager_service.h/.cpp` 与 mock 影子头（5 方法签名 + 会话操作权限校验 + Subscribe 配置校验 + 占位分支）、`auth_event_subscribe_manager.h/.cpp`（会话 nextEventIndex/timeoutAllowFlag、pending 键 (clientId,eventIndex)、超时处置落值、清理内部残留宏）、`auth_event_subscribe_client.h/.cpp`（CreatClient+timeoutAllowFlag 默认 true、恢复 ConstructClientId、SetAuthResult 附带 clientId）、`sg_collect_sdk.map` 无变化、各 BUILD.gn（services/SDK/SaTest/9 fuzz：开关条件编入）与测试文件（双形态编译验证通过）
- 核心实现：① HA 打点 AUTH_BLOCK_RESULT/AUTH_RESULT_TIMEOUT（适配层 + 起止毫秒时间戳 + 400ms 常量）；② 整需求 gni 开关 + 宏隔离（新文件整文件 #ifdef + BUILD 条件编入，关闭时 IPC 占位一律 FAILED，auth_event.cpp 无条件因 IDL 符号）；③ Destory/Subscribe/Unsubscribe 前置双轨校验（5 方法全覆盖）；④ Subscribe 事件配置校验（GetEventConfig）；⑤ 超时跟踪重构 (clientId, eventIndex)（多客户端/多次分发独立跟踪）；⑥ clientId 挪回客户端生成（SDK ConstructClientId，重复/空 → BAD_PARAM 真实可达）；⑦ 超时处置策略（创建时设置默认放行，超时未回填按策略落结果表，回填优先不覆盖）
- 设计偏差：已同步 dev-design 至 v7（本执行记录对应其"v7 变更"清单）
- 待处理：uid 白名单具体值待用户；ha_client_lite_api.h 依赖进仓后替换 ReportToHa 日志兜底（单点）；上机集成验证沿用 T3 登记项
- 后续须知：无
- 证据：每轮变更后 `hb build security_guard -t` 编译通过；宏隔离双形态（开/关）均验证编译通过后恢复默认 false；单测累计 42 例（parcelable 3 + 管理器 31 + SDK 8，管理器含 Timeout001-004/TimeoutAction001-002/SessionApiPermission001-002/SubscribeEventIdNotInConfig001 等增量用例）

### T5：增量迭代（移除超时特性 + 会话即远端对象重构 + 错误码梳理）

- 状态：Completed
- 修改文件：新增 `services/data_collect/idl/AuthEventSession.idl`、`services/data_collect/sa/include/auth_event_session_service.h`、`services/data_collect/sa/auth_event_session_service.cpp`（会话对象 + per-session DeathRecipient）；修改 `DataCollectManagerIdl.idl`（5 方法收缩为 1 方法 `CreatAuthEventClient([in] IRemoteObject cb, [out] IRemoteObject session)`，实测 IDL 支持 [out] IRemoteObject）、`idl/BUILD.gn`（+auth_event_session_interface target 与 stub/proxy source_set）、`data_collect_manager_service_ipc_interface_code.h`（登记码收缩为 13 一个）、`auth_event_subscribe_manager.h/.cpp`（重写：会话集合 set<sptr<AuthEventSessionService>>、结果表、配额、双轨校验 IsCallerAllowed 静态方法自服务类迁入、NotifyAuthEvent 保留、超时跟踪全删）、`auth_event_session_service.*`（四方法：权限→会话有效性→pid 归属→配置校验→转调 manager）、`data_collect_manager_service.h/.cpp` 与 mock 影子头（1 方法签名）、`auth_event_reporter.h/.cpp`（删 ReportAuthResultTimeout/NowMs，仅留 AUTH_BLOCK_RESULT）、`auth_event_subscribe_client.h/.cpp`（重写：sessionRemote_ 成员直调、删 clientId/timeoutAllowFlag/ConstructClientId、重连重建会话）、9 个 fuzz BUILD.gn 与 services/SDK/SaTest BUILD.gn（+session_service 源与 stub 依赖；修复 v8 遗留的 libsg_collect_sdk 及其测试 target 缺 defines 注入问题）、两个测试文件（删 6 超时用例、session 语义重写）
- 核心实现：① **移除服务端事件超时判断**（用户明确属另一需求）：pendingResults_/CheckAuthResultTimeout/AUTH_RESULT_TIMEOUT_MS/timeoutAllowFlag/seqNum 填充解析/AUTH_RESULT_TIMEOUT 打点全删；② **方案 D 会话即远端对象**（用户裁决）：主接口仅 1 方法，服务端创建 AuthEventSessionService（stub 实例即会话状态容器）经 [out] 下发代理，SDK 持 sessionRemote_ 直调四方法——零身份参数、服务端零会话查表、死亡清理 per-session DeathRecipient 自治（O(1)）；③ 用户裁决语义：Unsubscribe 未订阅幂等 SUCCESS、同 cb 重复创建 BAD_PARAM、Destroy 幂等 SUCCESS 且销毁后其他方法 BAD_PARAM；④ 错误码场景全量矩阵落设计文档 4.9/详设 1.2.2（全部复用既有 ErrorCode，不新增码）
- 设计偏差：已同步 dev-design 至 v9；`.sdd/SR20260806903405/详细设计.md` 按 v9 全文重写
- 待处理：uid 白名单具体值仍待用户；ha_client_lite_api.h 依赖进仓后替换 ReportToHa 日志兜底；上机集成验证沿用 T3 登记项
- 后续须知：v9 后主接口 wire code 仅新增 1 个（code 20）；会话方法走独立 AuthEventSessionIpcCode 空间（1-4）
- 追加变更（同批次）：① timeoutAllowFlag 参数保留——IDL/SDK/会话链路恢复携带并随会话保存（GetTimeoutAllowFlag），本需求仅保存不消费，供超时需求（另一需求）届时按会话读取；SDK 重连重建沿用；新增 TimeoutPolicyStorage001 用例（会话策略存取）。② 对外头文件随 gni 开关暴露——5 个对外头（auth_event.h/i_auth_event_callback.h/auth_event_callback_service.h/auth_event_callback_stub.h/auth_event_subscribe_client.h）自 bundle.json header_base 登记目录 interfaces/inner_api/collect/include/ 迁至 frameworks/common/collect/include/auth_event/（仓内先例：SDK 回调适配头本在 frameworks/common/collect/include）；对外暴露唯一通道为 libsg_collect_sdk public_configs（security_guard_config）在 gni 开启时追加该目录；同步更新 22 个 BUILD.gn 的仓内 include 路径（IDL config/服务端/SaTest/SDK test/inner_api test/19 个 fuzz）。双形态 ninja 产物验证：默认关闭时消费方（napi、security_collector）编译命令不含该目录（头文件完全不对外）；开启时经 public_configs 自动获得。
- 证据：`hb build security_guard -t --gn-args security_guard_auth_event_enable=true` 与默认 false 双形态编译全绿；开启形态产物 llvm-nm 验证（libsg_collect_sdk.z.so AuthEventSubscribeClient 6 导出 + 0 undefined AuthEvent；libsg_collect_service.z.so AuthEventSessionService 32 符号）；单测编译产物验证（SaTest 27 例注册 + SDK test 8 例注册 + parcelable 3 例 = 38 例，ARM 产物运行需真机）
