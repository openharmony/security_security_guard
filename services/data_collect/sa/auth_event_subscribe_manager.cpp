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

#include "auth_event_subscribe_manager.h"

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <vector>

#include "nlohmann/json.hpp"

#include "auth_event_callback_proxy.h"
#include "auth_event_reporter.h"
#include "i_auth_event_callback.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
namespace OHOS::Security::SecurityGuard {
namespace {
constexpr const char* METADATA_KEY_SEQ_NUM = "seqNum";

// 将分发索引 seqNum 以 JSON 键写入 metadata：metadata 为空或 JSON 对象则合并，非 JSON 则覆盖并告警
void FillSeqNumToMetadata(AuthEvent &event, int64_t seqNum)
{
    nlohmann::json meta = nlohmann::json::object();
    if (!event.GetMetadata().empty()) {
        nlohmann::json parsed = nlohmann::json::parse(event.GetMetadata(), nullptr, false);
        if (parsed.is_object()) {
            meta = parsed;
        } else {
            SGLOGW("metadata is not json object, overwrite with seqNum only");
        }
    }
    meta[METADATA_KEY_SEQ_NUM] = seqNum;
    event.SetMetadata(meta.dump());
}

// 从 metadata 解析分发索引 seqNum；不存在或格式非法返回 false
bool ParseSeqNumFromMetadata(const AuthEvent &event, int64_t &seqNum)
{
    if (event.GetMetadata().empty()) {
        return false;
    }
    nlohmann::json meta = nlohmann::json::parse(event.GetMetadata(), nullptr, false);
    if (!meta.is_object() || !meta.contains(METADATA_KEY_SEQ_NUM)) {
        return false;
    }
    if (!meta[METADATA_KEY_SEQ_NUM].is_number_integer()) {
        return false;
    }
    seqNum = meta[METADATA_KEY_SEQ_NUM].get<int64_t>();
    return true;
}
}

AuthEventSubscribeManager& AuthEventSubscribeManager::GetInstance()
{
    static AuthEventSubscribeManager instance;
    return instance;
}

AuthEventSubscribeManager::AuthEventSubscribeManager()
{
    deathRecipient_ = new (std::nothrow) SubscriberDeathRecipient();
    // 允许接入的 native token uid 白名单：具体值待产品确认后补入；
    // 空清单表示暂拒所有 native token 接入，补值后即生效。
    allowedUids_ = {};
}

AuthEventSubscribeManager::~AuthEventSubscribeManager() = default;

bool AuthEventSubscribeManager::IsUidAllowed(int32_t uid) const
{
    return std::find(allowedUids_.begin(), allowedUids_.end(), uid) != allowedUids_.end();
}

int32_t AuthEventSubscribeManager::CheckQuotaLocked(pid_t callerPid) const
{
    if (sessionsMap_.size() >= MAX_AUTH_EVENT_CLIENT_SIZE) {
        SGLOGE("max client size limited");
        return CLIENT_EXCEED_GLOBAL_LIMIT;
    }
    size_t pidClientCount = 0;
    for (const auto &iter : sessionsMap_) {
        if (iter.second != nullptr && iter.second->pid == callerPid) {
            ++pidClientCount;
        }
    }
    if (pidClientCount >= MAX_AUTH_EVENT_CLIENT_SIZE_ONE_PROCESS) {
        SGLOGE("max client size one process limited");
        return CLIENT_EXCEED_PROCESS_LIMIT;
    }
    return SUCCESS;
}

std::shared_ptr<AuthEventSubscribeManager::AuthEventClientSession> AuthEventSubscribeManager::FindSessionLocked(
    const std::string &clientId) const
{
    auto iter = sessionsMap_.find(clientId);
    if (iter == sessionsMap_.end() || iter->second == nullptr) {
        return nullptr;
    }
    return iter->second;
}

int32_t AuthEventSubscribeManager::CreatAuthEventClient(const std::string &clientId, bool timeoutAllowFlag,
    pid_t callerPid, int32_t callerUid, const sptr<IRemoteObject> &callback)
{
    if (callback == nullptr) {
        SGLOGE("callback is null");
        return NULL_OBJECT;
    }
    if (clientId.empty()) {
        SGLOGE("clientId is empty");
        return BAD_PARAM;
    }
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        int32_t code = CheckQuotaLocked(callerPid);
        if (code != SUCCESS) {
            return code;
        }
        if (sessionsMap_.find(clientId) != sessionsMap_.end()) {
            SGLOGE("clientId exist");
            return BAD_PARAM;
        }
        auto session = std::make_shared<AuthEventClientSession>();
        session->pid = callerPid;
        session->uid = callerUid;
        session->timeoutAllowFlag = timeoutAllowFlag;
        session->callback = callback;
        sessionsMap_[clientId] = session;
    }
    // AddDeathRecipient 是跨进程调用，放锁外执行；失败则回滚会话，避免孤儿会话占用配额
    if (deathRecipient_ == nullptr || !callback->AddDeathRecipient(deathRecipient_)) {
        SGLOGE("add death recipient fail");
        std::lock_guard<ffrt::mutex> lock(mutex_);
        sessionsMap_.erase(clientId);
        return FAILED;
    }
    SGLOGI("create auth event client, clientId=%{private}s, pid=%{public}d", clientId.c_str(),
        static_cast<int32_t>(callerPid));
    return SUCCESS;
}

int32_t AuthEventSubscribeManager::DestoryAuthEventClient(const std::string &clientId, pid_t callerPid)
{
    sptr<IRemoteObject> callback {};
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        auto session = FindSessionLocked(clientId);
        if (session == nullptr) {
            SGLOGE("clientId not found");
            return BAD_PARAM;
        }
        if (session->pid != callerPid) {
            SGLOGE("clientId not belong to caller");
            return BAD_PARAM;
        }
        callback = session->callback;
        sessionsMap_.erase(clientId);
    }
    // RemoveDeathRecipient 是跨进程调用，放锁外执行
    if (callback != nullptr && deathRecipient_ != nullptr) {
        callback->RemoveDeathRecipient(deathRecipient_);
    }
    SGLOGI("destroy auth event client, clientId=%{private}s", clientId.c_str());
    return SUCCESS;
}

int32_t AuthEventSubscribeManager::SubscribeAuthEvent(int64_t eventId, const std::string &clientId, pid_t callerPid)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto session = FindSessionLocked(clientId);
    if (session == nullptr) {
        SGLOGE("clientId not found");
        return BAD_PARAM;
    }
    if (session->pid != callerPid) {
        SGLOGE("clientId not belong to caller");
        return BAD_PARAM;
    }
    if (session->eventIds.size() >= MAX_AUTH_EVENT_SUBSCRIBE_SIZE) {
        SGLOGE("subscribe size limited");
        return FILTER_EXCEED_LIMIT;
    }
    session->eventIds.insert(eventId);
    SGLOGI("subscribe auth event, eventId=%{public}" PRId64 ", clientId=%{private}s", eventId, clientId.c_str());
    return SUCCESS;
}

int32_t AuthEventSubscribeManager::UnsubscribeAuthEvent(int64_t eventId, const std::string &clientId, pid_t callerPid)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto session = FindSessionLocked(clientId);
    if (session == nullptr) {
        SGLOGE("clientId not found");
        return BAD_PARAM;
    }
    if (session->pid != callerPid) {
        SGLOGE("clientId not belong to caller");
        return BAD_PARAM;
    }
    session->eventIds.erase(eventId);
    SGLOGI("unsubscribe auth event, eventId=%{public}" PRId64 ", clientId=%{private}s", eventId, clientId.c_str());
    return SUCCESS;
}

int32_t AuthEventSubscribeManager::SetAuthResult(pid_t callerPid, int32_t callerUid,
    const std::string &clientId, const AuthEvent &event, bool allowFlag)
{
    if (event.GetContent().size() > MAX_AUTH_EVENT_STR_LEN || event.GetMetadata().size() > MAX_AUTH_EVENT_STR_LEN) {
        SGLOGE("content or metadata too long");
        return BAD_PARAM;
    }
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        auto session = FindSessionLocked(clientId);
        if (session == nullptr) {
            SGLOGE("clientId not found");
            return BAD_PARAM;
        }
        if (session->pid != callerPid) {
            SGLOGE("clientId not belong to caller");
            return BAD_PARAM;
        }
        if (authResults_.find(event.GetEventId()) == authResults_.end() &&
            authResults_.size() >= MAX_AUTH_EVENT_RESULT_SIZE) {
            SGLOGE("auth result size limited");
            return FILTER_EXCEED_LIMIT;
        }
        authResults_[event.GetEventId()] = allowFlag;
        // 该客户端该次分发的结果已回填，仅取消自己的超时跟踪（其余客户端独立跟踪）；
        // 分发索引 seqNum 从回填事件的 metadata JSON 中解析
        int64_t seqNum = 0;
        if (ParseSeqNumFromMetadata(event, seqNum)) {
            pendingResults_.erase(PendingKey {clientId, seqNum});
        }
    }
    // HA 打点：仅阻断结果上报（耗时接口，锁外执行）
    if (!allowFlag) {
        AuthEventReporter::ReportAuthBlockResult(callerPid, callerUid, event);
    }
    SGLOGI("set auth result, eventId=%{public}" PRId64 ", allowFlag=%{public}d", event.GetEventId(),
        static_cast<int32_t>(allowFlag));
    return SUCCESS;
}

int32_t AuthEventSubscribeManager::GetAuthResult(int64_t eventId, bool &allowFlag)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto iter = authResults_.find(eventId);
    if (iter == authResults_.end()) {
        return NOT_FOUND;
    }
    allowFlag = iter->second;
    return SUCCESS;
}

void AuthEventSubscribeManager::NotifyAuthEvent(const AuthEvent &event)
{
    if (event.GetContent().size() > MAX_AUTH_EVENT_STR_LEN || event.GetMetadata().size() > MAX_AUTH_EVENT_STR_LEN) {
        SGLOGE("content or metadata too long, discard event");
        return;
    }
    // 锁内快照命中会话（并按会话分配分发索引 eventIndex），锁外执行推送，避免持锁跨进程调用
    std::vector<sptr<IRemoteObject>> callbacks {};
    std::vector<AuthEvent> eventsToPush {};
    std::vector<std::string> pushClientIds {};
    std::vector<int64_t> pushEventIndexes {};
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        int64_t nowMs = AuthEventReporter::NowMs();
        for (const auto &iter : sessionsMap_) {
            if (iter.second == nullptr || iter.second->callback == nullptr) {
                continue;
            }
            if (iter.second->eventIds.find(event.GetEventId()) == iter.second->eventIds.end()) {
                continue;
            }
            // 每会话分发计数器递增，事件副本将 eventIndex 以 JSON 键 seqNum 填入 metadata
            int64_t eventIndex = iter.second->nextEventIndex++;
            AuthEvent pushEvent = event;
            FillSeqNumToMetadata(pushEvent, eventIndex);
            callbacks.push_back(iter.second->callback);
            eventsToPush.push_back(pushEvent);
            pushClientIds.push_back(iter.first);
            pushEventIndexes.push_back(eventIndex);
            // (clientId, eventIndex) 独立跟踪该次分发的回填
            auto pending = std::make_shared<PendingAuthResult>();
            pending->event = pushEvent;
            pending->startMs = nowMs;
            pending->pid = iter.second->pid;
            pending->uid = iter.second->uid;
            pending->timeoutAllowFlag = iter.second->timeoutAllowFlag;
            pendingResults_[PendingKey {iter.first, eventIndex}] = pending;
        }
    }
    for (size_t i = 0; i < callbacks.size(); i++) {
        auto proxy = iface_cast<IAuthEventCallback>(callbacks[i]);
        if (proxy == nullptr) {
            SGLOGE("auth event callback proxy is null");
            continue;
        }
        proxy->OnAuthEvent(eventsToPush[i]);
    }
    // 超时跟踪：每个分发实例独立延迟检查
    for (size_t i = 0; i < pushClientIds.size(); i++) {
        std::string clientId = pushClientIds[i];
        int64_t eventIndex = pushEventIndexes[i];
        ffrt::submit([clientId, eventIndex]() {
            ffrt::this_task::sleep_for(std::chrono::milliseconds(AUTH_RESULT_TIMEOUT_MS));
            AuthEventSubscribeManager::GetInstance().CheckAuthResultTimeout(clientId, eventIndex);
        });
    }
}

void AuthEventSubscribeManager::CheckAuthResultTimeout(const std::string &clientId, int64_t eventIndex)
{
    std::shared_ptr<PendingAuthResult> pending {};
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        auto iter = pendingResults_.find(PendingKey {clientId, eventIndex});
        if (iter == pendingResults_.end()) {
            return; // 该客户端该次分发已回填或已处理
        }
        pending = iter->second;
        pendingResults_.erase(iter);
        // 超时处置：该 eventId 尚无回填结果时，按客户端创建时设置的超时策略落值
        if (authResults_.find(pending->event.GetEventId()) == authResults_.end() &&
            authResults_.size() < MAX_AUTH_EVENT_RESULT_SIZE) {
            authResults_[pending->event.GetEventId()] = pending->timeoutAllowFlag;
        }
    }
    if (pending == nullptr) {
        return;
    }
    int64_t endMs = AuthEventReporter::NowMs();
    // HA 打点：该客户端该次分发回填超时（含起始/结束毫秒时间戳，耗时接口锁外执行）
    AuthEventReporter::ReportAuthResultTimeout(pending->pid, pending->uid, pending->event, pending->startMs,
        endMs);
    SGLOGI("auth result timeout, clientId=%{private}s, eventId=%{public}" PRId64 ", eventIndex=%{public}" PRId64,
        clientId.c_str(), pending->event.GetEventId(), eventIndex);
}

void AuthEventSubscribeManager::HandleSubscriberDied(const wptr<IRemoteObject> &remote)
{
    sptr<IRemoteObject> callback = remote.promote();
    if (callback == nullptr) {
        return;
    }
    bool removed = false;
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        for (auto iter = sessionsMap_.begin(); iter != sessionsMap_.end();) {
            if (iter->second != nullptr && iter->second->callback == callback) {
                iter = sessionsMap_.erase(iter);
                removed = true;
            } else {
                ++iter;
            }
        }
    }
    // RemoveDeathRecipient 是跨进程调用，放锁外执行
    if (removed && deathRecipient_ != nullptr) {
        callback->RemoveDeathRecipient(deathRecipient_);
    }
    SGLOGI("auth event subscriber died, clean sessions");
}

void AuthEventSubscribeManager::SubscriberDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    AuthEventSubscribeManager::GetInstance().HandleSubscriberDied(remote);
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
