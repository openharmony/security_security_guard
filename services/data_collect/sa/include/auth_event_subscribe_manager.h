/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
#ifndef SECURITY_GUARD_AUTH_EVENT_SUBSCRIBE_MANAGER_H
#define SECURITY_GUARD_AUTH_EVENT_SUBSCRIBE_MANAGER_H

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "ffrt.h"
#include "iremote_object.h"
#include "nocopyable.h"

#include "auth_event.h"

namespace OHOS::Security::SecurityGuard {
// 客户端配额：一个进程最多 2 个客户端，一个设备最多 16 个客户端
constexpr size_t MAX_AUTH_EVENT_CLIENT_SIZE_ONE_PROCESS = 2;
constexpr size_t MAX_AUTH_EVENT_CLIENT_SIZE = 16;
// AuthEvent 字符串字段长度上限，超限返回 BAD_PARAM
constexpr size_t MAX_AUTH_EVENT_STR_LEN = 4096;
// 单会话订阅 eventId 数量与结果状态表容量上限，超限返回 FILTER_EXCEED_LIMIT
constexpr size_t MAX_AUTH_EVENT_SUBSCRIBE_SIZE = 1024;
constexpr size_t MAX_AUTH_EVENT_RESULT_SIZE = 1024;
// 阻断结果回填超时时长（毫秒）：NotifyAuthEvent 分发后超时未回填则 HA 打点
constexpr int64_t AUTH_RESULT_TIMEOUT_MS = 400;
// HAP 应用接入所需权限
constexpr const char* AUTH_AUDIT_EVENT_PERMISSION = "ohos.permission.kernel.AUTH_AUDIT_EVENT";

class AuthEventSubscribeManager {
public:
    static AuthEventSubscribeManager& GetInstance();

    int32_t CreatAuthEventClient(const std::string &clientId, bool timeoutAllowFlag, pid_t callerPid,
        int32_t callerUid, const sptr<IRemoteObject> &callback);
    int32_t DestoryAuthEventClient(const std::string &clientId, pid_t callerPid);
    int32_t SubscribeAuthEvent(int64_t eventId, const std::string &clientId, pid_t callerPid);
    int32_t UnsubscribeAuthEvent(int64_t eventId, const std::string &clientId, pid_t callerPid);
    int32_t SetAuthResult(pid_t callerPid, int32_t callerUid, const std::string &clientId,
        const AuthEvent &event, bool allowFlag);
    int32_t GetAuthResult(int64_t eventId, bool &allowFlag);
    // 内部事件源注入入口：按各会话已订阅 eventId 分发推送（本期预留），并登记回填超时跟踪
    void NotifyAuthEvent(const AuthEvent &event);
    // 允许接入 AuthEvent 框架的 SA 应用（native token）uid 白名单查询。
    // 具体值待产品确认后补入；空清单表示暂拒所有 native token 接入。
    bool IsUidAllowed(int32_t uid) const;

private:
    AuthEventSubscribeManager();
    ~AuthEventSubscribeManager();
    DISALLOW_COPY_AND_MOVE(AuthEventSubscribeManager);
    class SubscriberDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        SubscriberDeathRecipient() = default;
        ~SubscriberDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };

    struct AuthEventClientSession {
        pid_t pid {};
        int32_t uid {};
        sptr<IRemoteObject> callback {};
        std::set<int64_t> eventIds {};
        int64_t nextEventIndex {1}; // 每会话事件分发计数器，分发时递增
        bool timeoutAllowFlag {true}; // 回填超时处置策略（创建时设置，默认放行）
    };

    // 回填超时跟踪：NotifyAuthEvent 分发时按会话分配 eventIndex，
    // 以 (clientId, eventIndex) 唯一标识一次"向某客户端分发某事件"的待回填实例，
    // 同一 eventId 分发给多个客户端/多次分发各自独立跟踪；超时未回填则 HA 打点。
    struct PendingAuthResult {
        AuthEvent event {};
        int64_t startMs {}; // 分发时刻（毫秒时间戳）
        pid_t pid {};
        int32_t uid {};
        bool timeoutAllowFlag {true}; // 超时未回填时按该策略落结果（快照自会话）
    };
    struct PendingKey {
        std::string clientId {};
        int64_t eventIndex {0};
        bool operator<(const PendingKey &other) const
        {
            if (clientId != other.clientId) {
                return clientId < other.clientId;
            }
            return eventIndex < other.eventIndex;
        }
    };
    void CheckAuthResultTimeout(const std::string &clientId, int64_t eventIndex);

    int32_t CheckQuotaLocked(pid_t callerPid) const;
    std::shared_ptr<AuthEventClientSession> FindSessionLocked(const std::string &clientId) const;
    void HandleSubscriberDied(const wptr<IRemoteObject> &remote);

    // 锁纪律：mutex_ 同时保护 sessionsMap_、authResults_ 与 pendingResults_（会话数上限 16，
    // 临界区均为短内存操作，有意不分段锁）。临界区内禁止任何外部调用（binder 死亡通知
    // 注册/注销、IPC 推送、HA 打点），外部动作一律"锁内快照、锁外执行"。
    ffrt::mutex mutex_{};
    std::map<std::string, std::shared_ptr<AuthEventClientSession>> sessionsMap_{};
    std::map<int64_t, bool> authResults_{};
    std::map<PendingKey, std::shared_ptr<PendingAuthResult>> pendingResults_{};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_{};
    std::vector<int32_t> allowedUids_ {};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_SUBSCRIBE_MANAGER_H

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
