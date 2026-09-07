# 支持阻断服务使用者接入阻断框架 · dev 设计

> 状态：正式稿 v7（v6 + T3 后增量迭代：HA 打点、整需求宏隔离、会话操作权限/配置校验、pending 按 (clientId, eventIndex) 重构、clientId 改客户端生成、超时处置策略）
> v8 变更：分发索引不再作为 AuthEvent 独立字段（eventIndex_ 删除，parcelable 回归三字段），改为以 JSON 键 `seqNum` 填充在 metadata 中传输（服务端分发时 nlohmann 合并写入，客户端回填时解析；pending 内部键仍为 (clientId, eventIndex) 整数）。
> v7 变更：① 新增 HA 打点（AUTH_BLOCK_RESULT / AUTH_RESULT_TIMEOUT，适配层 AuthEventReporter，`ha_client_lite_api.h` 依赖未进仓先日志兜底）；② 整个需求经 gni 开关 `security_guard_auth_event_enable`（默认 false）+ 宏 `SECURITY_GUARD_AUTH_EVENT_ENABLE` 隔离；③ 会话操作（Destory/Subscribe/Unsubscribe）前置双轨校验，5 个 IPC 方法全覆盖；④ Subscribe 增加事件配置校验（GetEventConfig 未命中 → BAD_PARAM）；⑤ 超时跟踪重构为 `(clientId, eventIndex)` 键（AuthEvent 新增 eventIndex 字段、会话分发计数器、SetAuthResult 全链路带 clientId）；⑥ clientId 改回客户端生成（IDL 入参）；⑦ CreatClient 增加超时处置策略 timeoutAllowFlag（默认放行），超时未回填按策略落结果。
> v6 变更（T3 Review 落地）：① libsg_collect_sdk sources 编入 auth_event.cpp（so 符号自包含）；② sg_collect_sdk.map 导出 AuthEventSubscribeClient 5 方法与 AuthEvent 序列化/vtable/VTT 符号；③ HandleDeath 改为对齐 event_subscribe_client 的退避自动重连（{1,5,15,30,60×5}，重建后更新服务端新 clientId 并重订阅快照）；④ 新增 deleted_ 标志防护 DeleteClient/Deleter 与在途重连的会话复活竞态；⑤ Deleter 补 RemoveDeathRecipient；⑥ 影响面修正：bundle.json 无需修改（inner_kits 为 header_files 空数组 + header_base 目录登记，新头自动暴露，对齐仓库现状）。
> v5 变更（T2 Review 落地）：① 管理器实现路径 sa/（无 src/ 子目录，对齐仓库惯例）；② 会话操作（Subscribe/Unsubscribe/Destory）绑定 callerPid，不匹配返回 BAD_PARAM；③ 新增集合容量上限（单会话订阅数/结果表 1024，超限 FILTER_EXCEED_LIMIT）；④ uid 白名单改为管理器成员（空清单占位，补值即生效）；⑤ GetAuthResult(eventId, allowFlag) 作为预留读取口；⑥ clientId 日志 %{private}s。
> v4 变更：`CreatAuthEventClient` 的 clientId 改为服务端生成（时间戳 + 原子计数器）经 `[out]` 参数回传；SDK 删除客户端侧 `ConstructClientId` 自构造，保存服务端返回的 id 并在后续 Subscribe/Unsubscribe/Destory/SetAuthResult 中使用。
> v3 变更：新增 `SetAuthResult(AuthEvent, bool allowFlag)` IPC 与 SDK 接口——订阅者（服务使用者）作为决策方向框架回填某事件的阻断/放行结果；allowFlag 流向为 订阅者→框架，不随 OnAuthEvent 回调下发。
> v2 变更：`AuthEventSubscribeClient` 改为会话模式（CreatClient/Subscribe/Unsubscribe/DeleteClient + clientId），IDL 扩为多方法，取消 `AuthEventSubscribeInfo` 批量订阅结构，新增配额规格（进程 ≤2、设备 ≤16）。

## 1. 需求

### 1.1 目标

在 security_guard 仓库内新建"阻断服务使用者管理框架"：外部服务使用者（系统 SA / HAP 应用）通过 inner_api 客户端接入框架、订阅阻断（AuthEvent）事件通知，框架管理客户端会话与订阅关系、校验接入合法性、执行配额限制、向订阅者分发阻断事件。

### 1.2 范围边界

- 做：
  - 客户端会话管理 inner_api（挂 SA 3524 data_collect）：创建/销毁客户端会话、按 eventId 订阅/退订（对齐 `event_subscribe_client.h` 会话范式）；
  - HA 打点：AUTH_BLOCK_RESULT（阻断结果回填）/ AUTH_RESULT_TIMEOUT（回填超时，含起止毫秒时间戳），适配层 `AuthEventReporter` 单点接入 HA lite 客户端；
  - 超时处置策略：创建客户端时设置（阻断/放行，默认放行），超时未回填按策略落结果；
  - 整需求编译隔离：gni 开关 `security_guard_auth_event_enable`（默认 false，仅特定设备开启）；
  - 服务端会话与订阅管理（eventId 匹配分发、订阅者死亡清理）；
  - 配额限制：一个进程最多 2 个客户端，一个设备最多 16 个客户端（用户规格）；
  - 接入校验：SA 应用（native token）按硬编码 uid 清单校验；HAP 应用按权限名 `ohos.permission.kernel.AUTH_AUDIT_EVENT` 校验；
  - 结果回填：`SetAuthResult(AuthEvent, bool allowFlag)`——订阅者向框架设置某事件的阻断/放行结果（allowFlag 由订阅者下发，SDK 暴露，同套双轨校验）；
  - 客户端 SDK：新增 `AuthEventSubscribeClient` 类（含 SetAuthResult），编入 libsg_collect_sdk。
- 不做：
  - 阻断事件"产生源"（决策引擎、模型联动）——`SetAuthResult` 仅接收订阅者回填的处理结果，不做策略决策；服务端内部 `NotifyAuthEvent` 仍为预留注入口；
  - HiSysEvent 审计事件（打点走 HA 通道而非 HiSysEvent）；
  - 回填结果的下游消费链路（如内核同步取回结果的机制）——本期仅内存记录，预留读取口；
  - JS API；
  - 会话/订阅关系/回填结果持久化（不落库）；
  - HiSysEvent 审计事件；
  - 独立裁剪开关（随 security_guard_enable 整体裁剪）；
  - 权限定义登记（`ohos.permission.kernel.AUTH_AUDIT_EVENT` 的定义在 access_token 部件仓，本仓只做校验方引用）。

## 2. 现状摘要

无架构基线（`.sdd/software_architecture.md` 不存在），探索边界由需求文本与代码结构推断。本仓库现有 3 个 SA（3523 risk_classify / 3524 data_collect / 3525 security_collector），**无任何"阻断"相关实现，本框架为全新增量**。可直接复用的基础设施：IDL 代码生成 IPC（3524 现行方案）、**审计客户端会话管理范式（`EventSubscribeClient` + `AcquireDataSubscribeManager` 的 CreatClient/DestoryClient/Subscribe/Unsubscribe + clientId 会话表 + 配额检查 `IsExceedLimited`，本设计直接对齐该范式）**、双端回调 broker 模式、AccessTokenKit 权限校验、ffrt 并发、`SGLOGx` 日志。配额规格与现有审计会话限额同构：`MAX_SESSION_SIZE_ONE_PROCESS=2`、`MAX_SESSION_SIZE=16`（`acquire_data_subscribe_manager.cpp:46-47`），错误码 `CLIENT_EXCEED_PROCESS_LIMIT=1007`/`CLIENT_EXCEED_GLOBAL_LIMIT=1008` 已存在（`security_guard_define.h:45-46`），直接复用。关键改造点：3524 的 IDL 与服务类追加 4 个方法、新增服务端会话管理器与客户端 SDK 类、bundle.json inner_kits 头文件清单追加。

## 3. 方案

- 方案：在 SA 3524（data_collect）上扩展"AuthEvent 客户端会话 + 订阅通知 + 结果回填"能力，整体对齐现有审计客户端会话范式（`EventSubscribeClient`/`CreatClient`/`DestoryClient` IPC 链路）。服务使用者经 `AuthEventSubscribeClient::CreatClient(callback, client)` 创建会话；SDK 持有回调 service 与 clientId，按 eventId 逐个 `Subscribe/Unsubscribe`；订阅者作为决策方经 `SetAuthResult(event, allowFlag)` 向框架回填阻断/放行结果；销毁时 `DeleteClient` 断开回调并清理会话（shared_ptr Deleter 自动兜底）。服务端 `AuthEventSubscribeManager` 维护会话表（clientId → {回调远端对象, callerPid, 已订阅 eventIds 集合}）与结果状态表（eventId → allowFlag，内存），在 `CreatAuthEventClient` 处执行双轨权限校验 + 配额检查（进程 ≤2、设备 ≤16），由服务端内部预留的 `NotifyAuthEvent` 注入事件并按各会话已订阅 eventId 分发推送；订阅者进程死亡时自动清理会话。
- 备选考虑：
  - 新建独立 SA / 挂 3523 / 挂 3525 —— 未采纳：用户已定挂 3524（常驻进程、会话/订阅基础设施最全、免新增 SA 号与 init cfg）；
  - 查询式（pull）或组合模式 —— 未采纳：用户已定全局订阅通知模式；
  - IDL 代码生成 vs 手写 IPC —— 选 IDL（3524 现行方案）；
  - 构造函数式门面类（v1 草案）vs 会话式客户端 —— 未采纳 v1：用户明确要求对齐 `event_subscribe_client.h` 的 CreatClient/DeleteClient/Subscribe/Unsubscribe 会话接口；随之取消 `AuthEventSubscribeInfo` 批量订阅结构，改为按 eventId 逐个订阅；
  - 复用审计会话表（共享配额）vs 独立会话表 —— 选独立会话表：AuthEvent 客户端配额独立计数，不挤占现有审计客户端 16/2 配额，对既有行为零影响。

### 3.1 关键流程/状态变化

- 创建会话：使用者调 `AuthEventSubscribeClient::CreatClient(callback, client, timeoutAllowFlag=true)` → SDK 构造本地回调 service（`AuthEventCallbackService` 包 `std::function`）并生成 clientId（时间戳 + 回调指针 hash，对齐 event_subscribe_client 范式）→ 现取 SA 3524 proxy 调 `CreatAuthEventClient(clientId, timeoutAllowFlag, callbackRemote)` → 服务端依次执行：双轨校验 → 回调判空 → clientId 空/撞表检查（`BAD_PARAM`）→ 配额检查（该 callerPid 名下 clientId 数 <2 且会话表总数 <16）→ 登记会话表（含 DeathRecipient，失败回滚）；SDK 保存 clientId，后续 Subscribe/Unsubscribe/Destory 均携带它。
- 订阅：`client->Subscribe(eventId)` → proxy 调 `SubscribeAuthEvent(eventId, clientId)` → 服务端双轨校验 → clientId 判空 → **事件配置校验**（`ConfigDataManager::GetEventConfig` 未命中 → `BAD_PARAM`，对齐 CollectorStart 范式）→ 会话 eventIds 集合登记（重复登记幂等，单会话上限 1024）。
- 分发（预留源触发）：内部生产者调 `AuthEventSubscribeManager::NotifyAuthEvent(event)` → 锁内按命中会话逐个分配 `eventIndex`（会话 `nextEventIndex` 计数器递增）并快照（回调 + 将 eventIndex 以 JSON 键 `seqNum` 合入 metadata 的事件副本 + 超时跟踪登记 `(clientId, eventIndex) → pending{startMs, pid, uid, timeoutAllowFlag}`）→ 锁外逐客户端推送 `OnAuthEvent(事件副本)`（TF_ASYNC，不携带 allowFlag）→ 每个分发实例独立提交 400ms 延迟超时检查。
- 结果回填：订阅者完成决策后调 `client->SetAuthResult(event, allowFlag)`（event 为回调收到的事件副本，seqNum 在 metadata 中；SDK 自动附带自身 clientId）→ proxy 调 `SetAuthResult(event, allowFlag, clientId)` → 服务端双轨校验 → clientId 判空 → 按 clientId 定位会话并校验 pid 归属 → 记录结果状态表（eventId → allowFlag，覆盖更新，新键受 1024 上限）→ **解析 metadata 中 seqNum，仅取消该客户端该次分发 `(clientId, seqNum)` 的超时跟踪**（解析失败则不取消）（其他客户端/其他次分发不受影响）→ allowFlag=false 时锁外 HA 打点 AUTH_BLOCK_RESULT → `SUCCESS`。
- 退订：`client->Unsubscribe(eventId)` → 服务端双轨校验 → 从会话 eventIds 集合移除（不做配置校验：配置运行中可被移除）。
- 销毁：`client->DeleteClient()`（或最后一个 shared_ptr 释放触发 Deleter）→ proxy 调 `DestoryAuthEventClient(clientId)` → 断开回调（排空在途 OnAuthEvent）→ 服务端移除会话表项与 DeathRecipient。
- 异常：订阅者进程死亡 → DeathRecipient 回调 → 服务端移除该 pid 所属会话；服务端死亡 → SDK DeathRecipient 触发 HandleDeath 退避自动重连重建（新 clientId + 重订阅，对齐 EventSubscribeClient 范式）；调用方 DeleteClient 后重连被 deleted_ 标志终止。
- 配额超限：`CreatAuthEventClient` 时进程内已有 2 个 clientId → `CLIENT_EXCEED_PROCESS_LIMIT`；会话表已有 16 个 → `CLIENT_EXCEED_GLOBAL_LIMIT`；空/重复 clientId → `BAD_PARAM`（clientId 客户端生成，重复为真实可达路径）。
- 回填超时：分发实例 `(clientId, eventIndex)` 超过 `AUTH_RESULT_TIMEOUT_MS=400` 毫秒未回填 → 锁内**超时处置落值**（该 eventId 尚无回填结果时，按客户端创建时设置的 timeoutAllowFlag 写入结果表；回填结果优先不被覆盖；受结果表 1024 上限）→ 锁外 HA 打点 AUTH_RESULT_TIMEOUT（pid/uid + 事件信息 + START_TIME/END_TIME 毫秒时间戳）。
- 功能裁剪：gni 开关 `security_guard_auth_event_enable=false`（默认）时，5 个 IPC 入口退化为占位实现（一律 `FAILED`），功能源不编入，对既有 3524 零影响；`auth_event.cpp` 与其单测无条件编入（IDL 生成 stub/proxy 引用其序列化符号）。

## 4. 契约变更

命名空间统一 `OHOS::Security::SecurityGuard`。

### 4.1 数据结构（新增）

- `AuthEvent : Parcelable` — 头文件 `interfaces/inner_api/collect/include/auth_event.h`
  - 字段（三字段）：`int64_t eventId`（阻断/鉴权事件标识）；`std::string content`（事件内容，JSON 扩展）；`std::string metadata`（元数据，JSON 扩展；**分发索引 seqNum 由服务端以 JSON 键填充于此，非独立字段**，客户端回填时由服务端解析以匹配待回填实例）；
  - 实现手写 `Marshalling/Unmarshalling`（对齐 `security_event.h:24-47` 范式），实现文件 `frameworks/common/collect/src/auth_event.cpp`。
- ~~`AuthEventSubscribeInfo`~~ — v2 取消（会话模式按 eventId 逐个订阅，无需批量结构）。

### 4.2 IPC 接口（3524 扩展，IDL 追加 5 方法）

- IDL `services/data_collect/idl/DataCollectManagerIdl.idl` 追加（sequenceable 区仅新增 `AuthEvent` 声明）：
  ```
  void CreatAuthEventClient([in] String clientId, [in] boolean timeoutAllowFlag, [in] IRemoteObject cb);
  void DestoryAuthEventClient([in] String clientId);
  void SubscribeAuthEvent([in] long eventId, [in] String clientId);
  void UnsubscribeAuthEvent([in] long eventId, [in] String clientId);
  void SetAuthResult([in] AuthEvent event, [in] boolean allowFlag, [in] String clientId);
  ```
  （命名对齐现有 `CreatClient/DestoryClient/Subscribe/Unsubscribe` 的既有拼写，包括 Destory 的历史拼写；`SetAuthResult` 采用正确拼写。**clientId 由客户端生成作为 `[in]` 入参**（v7 从服务端生成回迁）；`timeoutAllowFlag` 为该客户端的回填超时处置策略（默认放行）；`SetAuthResult` 的 clientId 用于精确定位回填会话（与 event 中回带的 eventIndex 联合取消超时跟踪）。）
- 接口码：`interfaces/inner_api/collect/include/data_collect_manager_service_ipc_interface_code.h` 的 `DataCollectManagerInterfaceCode` 追加登记：
  `CMD_CREAT_AUTH_EVENT_CLIENT = 13`、`CMD_DESTORY_AUTH_EVENT_CLIENT = 14`、`CMD_SUBSCRIBE_AUTH_EVENT = 15`、`CMD_UNSUBSCRIBE_AUTH_EVENT = 16`、`CMD_SET_AUTH_RESULT = 17`（现 1-12）。**注意（Review 修正）：该枚举为登记值，非 wire code——3524 实际 IPC code 由 IDL 生成枚举 `DataCollectManagerIdlIpcCode` 按方法声明顺序分配（新 5 方法位于末尾，实际 code 20-24）；既有 19 个方法的 code 值不变，兼容性不受影响。T2/T3 测试断言以生成枚举为准，SDK 一律走 IDL 生成 proxy，禁止手写 SendRequest 使用 13-17。**
- 服务端实现（生成 stub 的虚函数覆写，`ErrCode` 返回）：`DataCollectManagerService::CreatAuthEventClient / DestoryAuthEventClient / SubscribeAuthEvent / UnsubscribeAuthEvent / SetAuthResult`，位于 `services/data_collect/sa/`。

### 4.3 回调 broker（新增）

- `IAuthEventCallback : IRemoteBroker` — `interfaces/inner_api/collect/include/i_auth_event_callback.h`
  - `DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.DataCollectManager.AuthEventCallback")`
  - 接口码枚举 `AuthEventCallbackInterfaceCode { CMD_ON_AUTH_EVENT = 1 }`（同文件追加）+ broker 内 `CMD_ON_AUTH_EVENT`；
  - 方法：`virtual int32_t OnAuthEvent(const AuthEvent &event) = 0;`
- 客户端适配（`std::function<void(const AuthEvent&)>` → 远端对象，对齐 `acquire_data_manager_callback_service/stub.h` 范式）：`auth_event_callback_service.h`（继承 `AuthEventCallbackStub`）放 `interfaces/inner_api/collect/include/`，实现 `frameworks/common/collect/src/auth_event_callback_service.cpp`，编入 libsg_collect_sdk。
- 服务端推送代理：`services/data_collect/sa/include/auth_event_callback_proxy.h`（手写 `IRemoteProxy<IAuthEventCallback>` + `BrokerDelegator`，对齐 `risk_analysis_manager_callback_proxy.h:28-36` 范式）。

### 4.4 客户端 SDK（新增，libsg_collect_sdk 内）

- `AuthEventSubscribeClient` — 头文件 `interfaces/inner_api/collect/include/auth_event_subscribe_client.h`，实现 `frameworks/common/collect/src/auth_event_subscribe_client.cpp`，接口形状对齐 `event_subscribe_client.h:29-67`：
  ```cpp
  using AuthEventCallback = std::function<void(const AuthEvent &event)>;
  class AuthEventSubscribeClient {
  public:
      static int32_t CreatClient(AuthEventCallback callback,
          std::shared_ptr<AuthEventSubscribeClient> &client);
      int32_t Subscribe(int64_t eventId);
      int32_t Unsubscribe(int64_t eventId);
      int32_t SetAuthResult(const AuthEvent &event, bool allowFlag);  // 订阅者回填阻断/放行结果
      void DeleteClient();   // 断开已注册回调并排空在途 OnAuthEvent；最后一个 shared_ptr 释放时 Deleter 自动执行
  private:
      static void Deleter(AuthEventSubscribeClient *);
      void HandleDeath();
      sptr<AuthEventCallbackService> callback_;
      sptr<IRemoteObject::DeathRecipient> deathRecipient_{};
      std::string clientId_{};   // 服务端生成并回传，CreatClient 时填充
      std::set<int64_t> subscribedEventIds_{};
      bool deleted_ {false};     // 已销毁标记：阻止 HandleDeath 复活已删除会话
  };
  ```
  - 禁用拷贝；SDK 每次调用现取 SA 3524（`GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID)` + `iface_cast`，对齐 `event_subscribe_client.cpp` 的 ReconnectService 范式）；**clientId 由 SDK 生成**（`ConstructClientId`：steady_clock 时间戳 + 回调指针 hash，对齐 `event_subscribe_client.cpp:107` 范式；服务端死亡重连重建时重新生成）。
  - `CreatClient` 第三参数 `timeoutAllowFlag`（默认 true=放行）：该客户端的回填超时处置策略，会话保存并随重连重建沿用。
  - `SetAuthResult` 为会话方法：SDK 自动附带自身 clientId；event 应传回调收到的事件副本（含 eventIndex）。
  - 服务端死亡：DeathRecipient → `HandleDeath()` 退避自动重连重建（对齐 `event_subscribe_client.cpp:162-207` 范式：{1,5,15,30,60×5} 秒重试 → ReconnectService → CreatAuthEventClient 重建（获得新服务端 clientId 并锁内更新）→ 按快照重订阅）；`deleted_` 标志（DeleteClient/Deleter 置位）在每轮重试前与重建写回前检查，已删除则销毁新建会话并退出，防会话复活。

### 4.5 接入校验（新增，全部 5 个 IPC 方法前置共用）

- 权限名常量：`ohos.permission.kernel.AUTH_AUDIT_EVENT`（本仓仅校验引用，定义登记在 access_token 部件仓，不在本仓范围）。
- uid 白名单：管理器成员 `allowedUids_` + `IsUidAllowed(uid)`（`auth_event_subscribe_manager.h`；**具体值待用户提供，空清单占位=暂拒所有 native token，补值即生效**）。
- 校验函数 `IsCallerAllowedSubscribeAuthEvent()`（`services/data_collect/sa/data_collect_manager_service.cpp`，独立于现有 `g_apiPermissionsMap`，对齐 `IsCallerHasApiPermission` 的写法），**5 个 IPC 方法（Creat/Destory/Subscribe/Unsubscribe/SetAuthResult）前置共用**：
  1. `IPCSkeleton::GetCallingTokenID()` → `AccessTokenKit::GetAccessTokenType(callerToken)` 取 token 类型；
  2. native token（SA 应用）：校验 `IPCSkeleton::GetCallingUid()` 在 uid 白名单（管理器成员 `allowedUids_`，空清单=暂拒，补值即生效）内，不在则返回 `NO_PERMISSION`；
  3. HAP token：`AccessTokenKit::VerifyAccessToken(callerToken, "ohos.permission.kernel.AUTH_AUDIT_EVENT")` 为 GRANTED 放行，否则 `NO_PERMISSION`；
  4. 其他 token 类型：`NO_PERMISSION`。
- 会话操作在权限校验之外由"clientId 进程绑定"二次保证：服务端比对会话 `pid` 与 `IPCSkeleton::GetCallingPid()`，不一致返回 `BAD_PARAM`。
- **订阅配置校验**：`SubscribeAuthEvent` 在权限/会话校验后执行 `ConfigDataManager::GetEventConfig(eventId, config)`，未命中返回 `BAD_PARAM`（事件须在事件配置中，对齐 `CollectorStart` 范式）；`UnsubscribeAuthEvent` 不做配置校验（配置运行中可被移除）。

### 4.6 服务端会话管理器（新增）

- `AuthEventSubscribeManager`（`services/data_collect/sa/include/auth_event_subscribe_manager.h` + `src/`，单例，NoCopyable）：
  - `int32_t CreatAuthEventClient(const std::string &clientId, bool timeoutAllowFlag, pid_t callerPid, int32_t callerUid, const sptr<IRemoteObject> &callback);` — clientId 空/撞表校验（`BAD_PARAM`）+ 配额检查 + 登记会话（含 timeoutAllowFlag）
  - `int32_t DestoryAuthEventClient(const std::string &clientId, pid_t callerPid);` — 会话 pid 归属校验
  - `int32_t SubscribeAuthEvent(int64_t eventId, const std::string &clientId, pid_t callerPid);`（未找到/非本进程会话返回 `BAD_PARAM`；重复 eventId 幂等；单会话上限 1024）
  - `int32_t UnsubscribeAuthEvent(int64_t eventId, const std::string &clientId, pid_t callerPid);`
  - `int32_t SetAuthResult(pid_t callerPid, int32_t callerUid, const std::string &clientId, const AuthEvent &event, bool allowFlag);` — 按 clientId 定位会话（pid 归属校验）→ 记录结果状态表（覆盖更新，新键受 1024 上限）→ 仅取消 `(clientId, eventIndex)` 超时跟踪 → 阻断结果锁外 HA 打点
  - `void NotifyAuthEvent(const AuthEvent &event);` — 内部事件源注入入口（预留，本期无调用方）；按会话分配 eventIndex、逐实例登记超时跟踪
  - `void CheckAuthResultTimeout(const std::string &clientId, int64_t eventIndex);` — 超时判定：按策略落值（无回填结果时）+ HA 打点
  - 会话表：`clientId → {pid, uid, callback, set<int64_t> eventIds, nextEventIndex 计数器, timeoutAllowFlag}`；结果状态表：`map<int64_t, bool> authResults_`；**超时跟踪表：`map<PendingKey{clientId, eventIndex}, PendingAuthResult{event, startMs, pid, uid, timeoutAllowFlag}>`**（同一 eventId 多客户端/多次分发各自独立跟踪）；ffrt::mutex 保护，锁内快照、锁外推送/打点（对齐 `acquire_data_subscribe_manager.cpp:1122-1128` 锁纪律）；
  - 配额常量（置于该头文件）：`MAX_AUTH_EVENT_CLIENT_SIZE = 16`（设备全局）、`MAX_AUTH_EVENT_CLIENT_SIZE_ONE_PROCESS = 2`（单进程）；检查逻辑对齐 `IsExceedLimited`（`acquire_data_subscribe_manager.cpp:1132-1166`）：按 `IPCSkeleton::GetCallingPid()` 统计该 pid 名下 clientId 数 ≥2 → `CLIENT_EXCEED_PROCESS_LIMIT`；会话表总数 ≥16 → `CLIENT_EXCEED_GLOBAL_LIMIT`；
  - 订阅者死亡：DeathRecipient 回调按远端对象反查移除会话表项（同步清理其 pending 可选：pending 由各自延迟检查自然消费）。
  - 常量：配额 `MAX_AUTH_EVENT_CLIENT_SIZE=16 / ..._ONE_PROCESS=2`、字符串 `MAX_AUTH_EVENT_STR_LEN=4096`、集合 `MAX_AUTH_EVENT_SUBSCRIBE_SIZE / MAX_AUTH_EVENT_RESULT_SIZE=1024`、超时 `AUTH_RESULT_TIMEOUT_MS=400`。
- `DataCollectManagerService` 的 5 个 IPC 方法转调该管理器；校验函数置于服务类私有方法。

### 4.7 错误码 / 兼容

- 错误码复用 `ErrorCode` 枚举（`security_guard_define.h:22-49`）：`SUCCESS / FAILED / NO_PERMISSION / BAD_PARAM / NULL_OBJECT / NOT_FOUND`、配额专用 `CLIENT_EXCEED_PROCESS_LIMIT=1007 / CLIENT_EXCEED_GLOBAL_LIMIT=1008`、集合上限 `FILTER_EXCEED_LIMIT=1006`（均已存在，不新增错误码）。
- 兼容：纯增量接口，现有 3524 的 12 个接口码与行为不变；独立会话表不挤占审计客户端既有 16/2 配额；旧 SDK 不受影响；**gni 开关默认关闭时 5 个 IPC 入口退化为占位实现（一律 `FAILED`），功能源不编入，对既有功能零影响**。

### 4.8 HA 打点（新增）

打点通道为 HA lite 客户端（`ha_client_lite_api.h`，**依赖尚未进入本仓构建环境**）：封装为 `AuthEventReporter` 适配层（`services/data_collect/sa/auth_event_reporter.h/.cpp`），真实上报集中在 `ReportToHa()` 单点（当前 SGLOGI 日志兜底，头文件进仓后仅改该函数）；随整个需求宏隔离；`Write` 类耗时接口仅锁外调用。

| 事件 | 触发 | 字段 |
|---|---|---|
| AUTH_BLOCK_RESULT | SetAuthResult 成功且 allowFlag=false | CALLER_PID、CALLER_UID、EVENT_ID、CONTENT、METADATA |
| AUTH_RESULT_TIMEOUT | 分发实例 (clientId, eventIndex) 超 400ms 未回填 | CALLER_PID、CALLER_UID、EVENT_ID、CONTENT、METADATA、START_TIME、END_TIME（毫秒时间戳，差值即超时时长） |

## 5. 影响面

新增：

- `interfaces/inner_api/collect/include/auth_event.h` —— 新增：AuthEvent 结构
- `interfaces/inner_api/collect/include/i_auth_event_callback.h` —— 新增：回调 broker（含回调接口码枚举）
- `interfaces/inner_api/collect/include/auth_event_callback_service.h` —— 新增：客户端回调适配（service 继承手写 stub）
- `interfaces/inner_api/collect/include/auth_event_subscribe_client.h` —— 新增：SDK 会话客户端类
- `frameworks/common/collect/src/auth_event.cpp` —— 新增：AuthEvent 序列化实现
- `frameworks/common/collect/src/auth_event_callback_service.cpp` —— 新增：回调适配实现（含 stub OnRemoteRequest）
- `frameworks/common/collect/src/auth_event_subscribe_client.cpp` —— 新增：SDK 实现
- `services/data_collect/sa/include/auth_event_subscribe_manager.h` —— 新增：会话管理器（含配额/超时常量与 uid 白名单）
- `services/data_collect/sa/include/auth_event_reporter.h` —— 新增：HA 打点适配层
- `services/data_collect/sa/auth_event_subscribe_manager.cpp` —— 新增：会话管理器实现（sa/ 下，对齐仓库惯例，无 src/ 子目录）
- `services/data_collect/sa/include/auth_event_callback_proxy.h` —— 新增：服务端推送代理头
- `services/data_collect/sa/auth_event_callback_proxy.cpp` —— 新增：服务端推送代理实现
- `test/unittest/data_collect/sa/auth_event_subscribe_manager_test.cpp` —— 新增：管理器单测

修改：

- `security_guard.gni` —— 修改：新增 gni 开关 `security_guard_auth_event_enable`（默认 false），控制整需求编译隔离
- `services/data_collect/idl/DataCollectManagerIdl.idl` —— 修改：追加 4 方法 + AuthEvent sequenceable 声明
- `interfaces/inner_api/collect/include/data_collect_manager_service_ipc_interface_code.h` —— 修改：追加接口码 13-16
- `services/data_collect/sa/include/data_collect_manager_service.h` —— 修改：声明 4 方法、私有校验函数
- `services/data_collect/sa/data_collect_manager_service.cpp` —— 修改：实现 4 方法 + 双轨校验函数
- `services/data_collect/BUILD.gn` —— 修改：新增 auth_event.cpp 与服务端源文件
- `frameworks/common/collect/BUILD.gn` —— 修改：新增 SDK 源文件（auth_event/callback_service/subscribe_client）
- `frameworks/common/collect/sg_collect_sdk.map` —— 修改：导出 AuthEventSubscribeClient 5 方法与 AuthEvent 序列化/vtable/VTT 符号
- `frameworks/common/collect/test/BUILD.gn` —— 修改：测试 target 补 SDK 新源文件与新测试
- `bundle.json` —— 无需修改（inner_kits 为 header_files 空数组 + header_base 目录登记，新头自动暴露，对齐仓库现状）
- `test/unittest/data_collect/BUILD.gn` —— 修改：新增单测源文件（T2 已完成）

删除（v1 残留，v2 取消）：

- `interfaces/inner_api/collect/include/auth_event_subscribe_info.h`、`frameworks/common/collect/src/auth_event_subscribe_info.cpp` —— 若已创建则随 v2 修订移除

不改动：sa_profile/（复用 3524）、根 BUILD.gn、security_guard.gni、hisysevent.yaml。

## 6. 验收标准

- [x] 编译通过（双形态）：`security_guard_auth_event_enable=false`（默认）与 `=true` 两种 gni 配置下 `hb build security_guard -t` 均无错误；开启形态产物含功能符号，关闭形态 IPC 入口为占位（一律 FAILED）。
- [x] Parcelable 往返：`AuthEvent` 四字段（eventId/content/metadata/eventIndex）往返一致（全字段/缺省值/空 parcel，auth_event_parcelable_test.cpp 3 例）。
- [x] 双轨校验（5 方法前置）：native + uid 在清单（注入）→ SUCCESS；native 不在清单 / HAP+DENIED / 非法 token → NO_PERMISSION；HAP+GRANTED → SUCCESS（DualTrackCheck001-005 + SetAuthResultPermission001/002 + SessionApiPermission001/002）。
- [x] 订阅配置校验：eventId 不在事件配置 → BAD_PARAM；配置中 eventId 进入会话校验；退订不校验（SubscribeEventIdNotInConfig001）。
- [x] 配额限制：同 pid 第 3 个 → CLIENT_EXCEED_PROCESS_LIMIT；满 16 → CLIENT_EXCEED_GLOBAL_LIMIT；销毁后可重建（QuotaLimit001/002）。
- [x] clientId 客户端生成：重复/空 clientId → BAD_PARAM（CreatAuthEventClient001）。
- [x] 回填超时跟踪：(clientId, eventIndex) 独立登记/消费/幂等；同事件两次分发各自独立；多客户端同 eventId 一端回填不影响另一端；无订阅不登记（AuthResultTimeout001-004）。
- [x] 超时处置策略：创建设阻断 → 超时落值 false；默认放行落值 true；已回填结果不被超时覆盖（AuthResultTimeoutAction001/002）。
- [ ] 会话与订阅管理：单测覆盖——Creat 后 Subscribe(eventId) 并 Notify 命中推送；Notify 未订阅 eventId 不推送；Unsubscribe 后不再推送；DestoryClient 后会话移除（再 Subscribe 返回 BAD_PARAM）；Subscribe 重复 eventId 幂等。
- [ ] 结果回填：单测覆盖——SetAuthResult(event, allowFlag) 记录状态表（查询内部表验证 true/false 覆盖更新）；无会话调用方回填 → BAD_PARAM；权限校验复用双轨用例（NO_PERMISSION 路径）。
- [ ] 死亡清理：单测模拟订阅者远端对象死亡（触发 DeathRecipient）后 Notify 不再向其推送、且无崩溃。
- [ ] SDK 客户端：单测覆盖 CreatClient/Subscribe/Unsubscribe/SetAuthResult/DeleteClient 正确组包并调用 proxy（经 IDL 生成接口码到达服务端路径），回调 function 被触发。
- [ ] 回归：现有 3524 单测（test/unittest/data_collect/）全部仍通过。

## 7. 存疑

- uid 白名单（管理器成员 `allowedUids_`）的具体值待用户提供：空清单=暂拒所有 native token 接入，补值后即生效（单测已覆盖"补值生效"语义）。
- `ha_client_lite_api.h` 依赖需进入本仓构建环境后，将 `AuthEventReporter::ReportToHa()` 的日志兜底替换为真实 HA 上报（单点改动）。
- `ohos.permission.kernel.AUTH_AUDIT_EVENT` 需在 access_token 部件仓完成权限定义与开放范围登记（本仓外动作，需用户在对应仓推进；不推进则 HAP 侧校验永远 DENIED，但不影响框架代码交付）。
- T2 实现注意事项（Review 登记）：① 每次修改 `services/data_collect/sa/include/data_collect_manager_service.h` 必须同步 `test/unittest/data_collect/sa/data_collect_manager_service.h`（mock 影子头）；② `SetAuthResult`/`NotifyAuthEvent` 消费 `content`/`metadata` 时按不可信输入处理（长度上限校验，超限 `BAD_PARAM`，使用点再解析 JSON）。

## 8. 现状附录（取证全量）

来源：SubAgent 只读取证报告（2026-09-03）+ v2 修订补充取证，关键结论附 file:line。

### 8.1 整体架构与 SA 注册

- 三层划分：SG 接口层 / SG 基础服务层 / SG 安全模型（`README_zh.md:10-15`）；frameworks=基础功能、interfaces=inner_api、services=服务框架（`README_zh.md:27-37`）。
- 组件：component name `security_guard`，subsystem `security`，syscap `SystemCapability.Security.SecurityGuard`（`bundle.json:12-17`）。
- SA 注册现状：

| SA | 模块 | libpath | process | run-on-create |
|---|---|---|---|---|
| 3523 | risk_classify | libsg_classify_service.z.so | security_guard | true |
| 3524 | data_collect | libsg_collect_service.z.so | security_guard | true |
| 3525 | security_collector | libsecurity_collector_service.z.so | security_collector | false |

  证据：`sa_profile/3523.json:2-12`、`sa_profile/3524.json:2-12`、`sa_profile/3525.json:2-12`；SA ID 常量 `i_risk_analysis_manager.h:28`、`i_data_collect_manager.h:31`、`i_security_collector_manager.h:31`；`sa_profile/BUILD.gn:18-36`。
- 进程属性：uid/gid `security_guard`、apl `system_basic`、secon `u:r:security_guard:s0`、权限 COLLECT/QUERY_SECURITY_EVENT（`sa_profile/security_guard.cfg:14-39`）；数据目录 `/data/service/el1/public/security_guard{,/tmp}` 与数据库目录（同文件 line 6-10）。
- 各服务模块职责：
  - risk_classify：模型管理 + 检测插件（`services/risk_classify/include/risk_analysis_manager_service.h:34-39`、`model_manager.cpp:56-107`、`risk_analysis_manager_service.cpp:87-91`）；
  - data_collect：采集/订阅/查询/配置更新 + 审计客户端会话管理（`services/data_collect/sa/include/data_collect_manager_service.h:34-73`）；
  - config_manager：配置加载/缓存/更新，`InitConfig<T>` 模板（`services/config_manager/include/config_manager.h:24-44`），导出 C 符号 `InitAllConfig/UpdateConfig` 供 dlopen（`services/config_manager/src/interface.cpp:21-39`）；
  - collector_manager：进程内采集器 so 加载（`services/collector_manager/include/data_collection.h:35-47`）；
  - security_collector：对"采集器使用者"开放的 SA，手写 IPC，空闲自动卸载（`services/security_collector/src/security_collector_manager_service.cpp:60-86`）。

### 8.2 IPC 模式（新增服务应模仿的范式）

- inner_api SDK 客户端：静态单例 + 每次调用现取 RemoteObject + `iface_cast`（`frameworks/common/collect/src/data_collect_manager.cpp:40-44,86-93`）；classify 为函数式 API（`frameworks/common/classify/src/sg_classify_client.cpp:42-66`）。
- **会话式客户端范式（v2 对齐目标）**：`EventSubscribeClient`（`interfaces/inner_api/collect/include/event_subscribe_client.h:29-67`）：静态 `CreatClient(eventGroup, callback, shared_ptr&)` / `Subscribe(eventId)` / `Unsubscribe(eventId)` / `ClearCallBack()`；`ConstructClientId` 由回调 service 指针构造（`event_subscribe_client.cpp:107`）；shared_ptr Deleter 销毁时自动断连（`event_subscribe_client.cpp:54`）；DeathRecipient + `HandleDeath` + `ReconnectService` 重连重注册（`event_subscribe_client.cpp:147,173-184`）。
- 会话服务端范式：`DataCollectManagerService::CreatClient(eventGroup, clientId, cb)`（`data_collect_manager_service.cpp:1202-1245`）：权限检查 → XCollie → 判空 NULL_OBJECT → 管理器登记 → SetDeathCallBack → clientId 去重（重复 `BAD_PARAM`，line 1232-1237）。
- **配额检查范式**：`AcquireDataSubscribeManager::IsExceedLimited(clientId, eventGroup, callerPid)`（`acquire_data_subscribe_manager.cpp:1132-1166`）：会话计数 ≥ `MAX_SESSION_SIZE=16` → `CLIENT_EXCEED_GLOBAL_LIMIT`；同 pid clientId 数 ≥ `MAX_SESSION_SIZE_ONE_PROCESS=2` → `CLIENT_EXCEED_PROCESS_LIMIT`（常量 line 46-47）；错误码定义 `security_guard_define.h:45-46`。
- 同步等待：`std::promise/future` + 超时（classify 15000ms `sg_classify_client.cpp:34,96-100`；data_collect 10000ms）。
- 回调：客户端把 `std::function` 包成本地 stub 传给服务端（`data_collect_manager.cpp:99-104`、`sg_classify_client.cpp:58-62`）；死亡通知退避重订阅 {1,5,15,30,60...}s（`data_collect_manager.cpp:168-224`）。
- IDL 代码生成（现行主流）：`services/data_collect/idl/DataCollectManagerIdl.idl:21-41` + `idl_gen_interface`（`services/data_collect/idl/BUILD.gn:18-24`）+ stub/proxy source_set（同文件 35-46,70-81）；服务类继承生成 stub（`data_collect_manager_service.h:29,34`）。手写 IPC 仅 3525 保留（`security_collector_manager_stub.cpp:22-56`）。IDL 语法要点（本地 idl 工具实测）：void 方法生成 `ErrCode` 返回的 proxy/stub；`IRemoteObject` 参数名不可用 `callback`（需 `cb`）；文件名须与接口名一致；未使用的 sequenceable 声明安全。
- IPC 接口码：`enum class XxxInterfaceCode`（`data_collect_manager_service_ipc_interface_code.h:23-47`）；broker 描述符 `DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.DataCollectManager")`（`i_data_collect_manager.h:36`）。
- 服务注册：`REGISTER_SYSTEM_ABILITY_BY_ID` + `OnStart` 序列（dlopen config → Init → `Publish`）（`data_collect_manager_service.cpp:109,120-155`）。
- 权限校验：API→权限映射表 `g_apiPermissionsMap`（`data_collect_manager_service.cpp:78-90`）→ `IsCallerHasApiPermission`（753-796）：VerifyAccessToken + 系统应用判定，非系统应用 `NO_SYSTEMCALL`。

### 8.3 新增服务模块接线点

1. 根 `BUILD.gn` group（`BUILD.gn:24-32`）；2. `security_guard.gni` gn args（`security_guard.gni:16-36`）；3. `bundle.json` sub_component + inner_kits（`bundle.json:80-131`）；4. `sa_profile/<SAID>.json` + BUILD.gn sources；5. 模块 BUILD.gn 范式（`services/risk_classify/BUILD.gn:25-99`）：`subsystem_name="security"`、`part_name="security_guard"`、version_script .map、统一 sanitize 块（integer_overflow/ubsan/boundary_sanitize/cfi + pac_ret + _FORTIFY_SOURCE=2，`services/data_collect/BUILD.gn:84-100`）；6. external_deps 常用：`ipc:ipc_core`/`ipc_single`、`samgr:samgr_proxy`、`safwk:system_ability_fwk`、`hilog:libhilog`、`c_utils:utils`、`access_token:libaccesstoken_sdk`、`ffrt:libffrt`、`json:nlohmann_json_static`、`sqlite:sqlite`、`hisysevent`；7. IDL 目录模板 `services/data_collect/idl/BUILD.gn:18-103`；8. SDK `innerapi_tags = ["platformsdk","sasdk"]`（`frameworks/common/collect/BUILD.gn:26-30`）；9. 测试接线（根 `BUILD.gn:34-103`、`bundle.json:132-136`）；10. fuzz 构建引用 `data_collect_manager_service.cpp` 的 9 个 BUILD.gn 需同步新增源文件（若编译报缺符号）。

### 8.4 公共能力（可复用）

- 日志 `SGLOGx`（`frameworks/common/log/include/security_guard_log.h:18-35`，domain 0xD002F07）；工具 `SecurityGuardUtils`（`security_guard_utils.h:22-30`）、`FileUtil::ReadFileToStr`（`file_util.h:24-28`）、cJSON 封装（`json_util.h:22-33`）、nlohmann 封装 `JsonCfg::Unmarshal`（`json_cfg.h:32-66`）、`FdsanFd` RAII（`fdsan_fd.h:24-99`）、看门狗 `XCollie_Utils`（`xcollie_utils.h:22-34`）。
- 错误码：`ErrorCode` 枚举（`security_guard_define.h:22-49`：SUCCESS/FAILED/NO_PERMISSION/NO_SYSTEMCALL/BAD_PARAM/NULL_OBJECT/CLIENT_EXCEED_PROCESS_LIMIT=1007/CLIENT_EXCEED_GLOBAL_LIMIT=1008 等）；`ErrCode = int`（c_utils errors.h，经 iremote_broker.h 引入，预处理实测确认）。
- 注意：`frameworks/common/task_handler` 与 `frameworks/common/database` 目录已被删除（多个 BUILD.gn 残留引用）；当前异步/并发一律用 ffrt（`ffrt::submit/queue/thread/sleep_for/mutex`）。
- HiSysEvent：域 SECURITY_GUARD，9 个事件（`hisysevent.yaml:14-78`），统一 `BigData::ReportXxx`（`services/bigdata/src/bigdata.cpp:39-80`）。

### 8.5 risk_classify（阻断决策潜在输入源）

- IPC 接口：`RequestSecurityModelResult(devId, modelId, param, callback)` / `SetModelState` / `StartSecurityModel`（`i_risk_analysis_manager.h:30-44`）；回调 `ResponseSecurityModelResult(devId, modelId, result)`（line 46-55）。
- 结果语义：`RISK_STATUS="risk" / SAFE_STATUS="safe" / UNKNOWN_STATUS="unknown"`（`risk_analysis_define.h:24-26`）；非白名单 modelId 一律 unknown（`risk_analysis_manager_service.cpp:164-167`）。
- 进程内订阅：`IModelResultListener::OnChange(result)`（`i_model_result_listener.h:23-27`，非 IPC）；跨进程走 3523 IPC 客户端（`sg_classify_client.h:33-38`）。
- 模型插件协议：`IModel` + `GetModelApi` 工厂，dlopen 加载（`model_manager.cpp:74-95`）。

### 8.6 配置链路（后续扩展可复用）

- 路径：预置 `/system/etc/security_guard_*.json|cfg`，已生效 `/data/service/el1/public/security_guard/...`，待生效 tmp（`services/config_manager/include/config_define.h:41-57`）；优先 /data 回退 /system/etc（`event_config.cpp:34-59`）。
- 解析：nlohmann + `JsonCfg::Unmarshal`（`event_config.cpp:67,127`）→ `ConfigDataManager` 单例缓存（`config_data_manager.h:27-60`）。
- 初始化：SA OnStart dlopen libsg_config_manager.z.so 调 `InitAllConfig()`（`interface.cpp:21-34`；调用方 `risk_analysis_manager_service.cpp:70-82`）——服务间无依赖初始化的既定模式。
- 在线更新：`ConfigUpdate(fd, name)` IPC + 信任名单 `/system/etc/config_update_trust_list.json`（`data_collect_manager_service.cpp:827-907,941-957`）。

### 8.7 数据库能力（本期不使用，备查）

- 自研 sqlite 封装（非 RDB）：`SqliteHelper`（`store/include/sqlite_helper.h:32-73`）→ `Database`（`database.h:24-52`）→ `DatabaseHelper`（`database_helper.h:23-57`）→ `DatabaseManager` 门面 + `SubscribeDb` 监听（`database_manager.h:27-57`）；表 `risk_event/audit_event/app_info`（`store_define.h:36-38`）；库目录 `/data/service/el1/public/database/security_guard_service/`。
- 独立 so：`sg_collect_service_database`（`services/data_collect/BUILD.gn:143-197`）。

### 8.8 测试组织

- 目录：`test/unittest/<module>/`、fuzz `test/fuzztest/`；unittest target 统一 `part_name="security_guard"`、`subsystem_name="securitycloudgovernance"`（注意：与产品 subsystem `security` 不一致，历史遗留，`test/unittest/data_collect/BUILD.gn:17-21`）。
- mock 模式：mock 头目录 `test/unittest/mock/*`（12 组），静态单例 + MOCK_METHOD，测试 cpp 手动定义 mock 静态成员 + `#define private public`（`security_guard_data_collect_sa_test.cpp:35-65`）；被测 .cpp 直接编进 unittest target（`test/unittest/risk_classify/BUILD.gn:49-62`）。
- 配额相关既有单测：`security_guard_data_collect_sa_test.cpp:1372`、`security_guard_data_collect_sa_new_test.cpp:260`（CLIENT_EXCEED_PROCESS_LIMIT 断言范式）。
- cfi_blocklist 仅 config_manager 测试使用（`test/unittest/config_manager/BUILD.gn:144-151`）。
- 陈旧引用：`services/risk_collect`、`frameworks/common/task_handler`、`frameworks/common/database` 的 BUILD.gn include 为死引用，新模块勿模仿。

### 8.9 隐含约定

- 命名空间 `OHOS::Security::SecurityGuard`；接口 `I` 前缀；文件 `i_xxx.h`/`xxx_client`/`xxx_service`/`xxx_stub`/`xxx_proxy`/`xxx_callback_{service,stub,proxy}`；SA id 常量 `XXX_SA_ID`；错误码 `ErrCode`/`int32_t` + `ErrorCode` 枚举。
- 服务类形状：`class XxxService : public SystemAbility, public XxxStub, public NoCopyable` + `DECLARE_SYSTEM_ABILITY`（`risk_analysis_manager_service.h:26-27`）。
- 日志格式 `SGLOGx("[%{public}s]" fmt, __func__, ...)`，隐私参数 `%{private}`；hidumper 覆写 `Dump(fd,args)`；系统参数未使用（配置全走文件）；so 用 version_script 只导出必要符号；并发统一 ffrt，"锁内快照、锁外执行"纪律。
- 编译环境：本机为部件独立编译 `hb build security_guard -t`（ARM 交叉编译，工作目录 /home/wangyi/code），非 README 的 rk3568 build.sh；单测产物为 ARM 可执行，运行需上机。
