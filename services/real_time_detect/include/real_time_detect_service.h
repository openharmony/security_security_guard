/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SECURITY_GUARD_REAL_TIME_DETECT_SERVICE_H
#define SECURITY_GUARD_REAL_TIME_DETECT_SERVICE_H

#include <future>
#include <chrono>
#include <queue>
#include <set>
#include <mutex>
#include <condition_variable>
#include <ability_connect_callback_stub.h>
#include "singleton.h"
#include "nocopyable.h"
#include "system_ability.h"
#include "extension_manager_client.h"

#include "security_event_query_callback.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "real_time_detect_stub.h"
#include "real_time_detect_callback_proxy.h"
#include "i_collector_subscriber.h"

namespace OHOS::Security::SecurityGuard {

typedef uint32_t (*ReadRpmbFunc)(uint32_t, uint8_t *, uint32_t);
typedef uint32_t (*WriteRpmbFunc)(uint32_t, const uint8_t *, uint32_t);

class RealTimeDetectService : public SystemAbility, public RealTimeDetectStub, public NoCopyable {
    DECLARE_SYSTEM_ABILITY(RealTimeDetectService);

public:
    RealTimeDetectService(int32_t saId, bool runOnCreate);
    ~RealTimeDetectService() override = default;
    void OnStart() override;
    void OnStop() override;
    bool GetEventList(std::vector<int64_t> &eventsId, std::vector<std::string> &eventsSecurityLevel);

private:
    class UploadManager : public Singleton<UploadManager> {
    public:
        static const int32_t QUEUE_MAX_SIZE = 100;
        const int32_t HSDR_INTERFACE_SIZE = 100;
        static const int32_t HSDR_INTERFACE_WAIT_TIME = 2000;
        static const int32_t RPMB_SIZE = 640;
        static const int32_t RPMB_START_POS = 0;
        static const int32_t RPMB_WRITE_MAX = 10;
        static const int32_t UPLOAD_PERIODICALLLY = 10;
        bool Init(std::vector<int64_t> eventsId, std::vector<std::string> eventsSecurityLevel);
        bool Publish(const SecurityCollector::Event &event);
        void Upload();
        void UploadTask();
        void AddQueue(const SecurityCollector::Event &event);
        void AddQueue(const int64_t &eventId);
        bool CallWriteRpmb();
        void SetReply(const std::vector<SecurityCollector::SecurityEvent> &events)
        {
            replyEvents = events;
        }
        std::vector<SecurityCollector::SecurityEvent> GetHsdrData()
        {
            return hsdrSendEvents;
        }
        void SetUploadStatus(const int32_t &status)
        {
            uploadStatus = status;
        }

    private:
        int32_t writeRpmbCount = 0;
        std::chrono::steady_clock::time_point callRpmbWriteTime{};
        std::vector<int64_t> eventsIdIndex;
        std::vector<std::string> eventsSecurityLevelIndex;
        std::condition_variable queueSendCond;
        std::mutex uploadQueueMutex;
        std::queue<SecurityCollector::Event> uploadQueue;
        std::set<int64_t> reportSuccessList;
        std::set<int64_t> reportFailedList;
        std::set<int64_t> oldReportFailedList;
        ReadRpmbFunc readRpmbFunc;
        WriteRpmbFunc writeRpmbFunc;
        void *handle;
        std::vector<SecurityCollector::SecurityEvent> replyEvents;
        std::vector<SecurityCollector::SecurityEvent> hsdrSendEvents;
        std::vector<std::vector<SecurityCollector::Event>> QueuePagination(const int32_t &size);
        int32_t uploadStatus = 1;
    };
    class SecurityGuardSubscriber : public SecurityCollector::ICollectorSubscriber {
    public:
        SecurityGuardSubscriber(SecurityCollector::Event event) : SecurityCollector::ICollectorSubscriber(event){};
        ~SecurityGuardSubscriber() override = default;
        int32_t OnNotify(const SecurityCollector::Event &event) override
        {
            return UploadManager::GetInstance().Publish(event) ? 0 : -1;
        };
    };
    class UploadQueryCallback : public SecurityEventQueryCallback {
    public:
        void OnQuery(const std::vector<SecurityCollector::SecurityEvent> &events) override
        {
            UploadManager::GetInstance().SetReply(events);
        };
        void OnComplete() override
        {
            SGLOGI("UploadQueryCallback OnComplete");
            queryCond.notify_one();
        };
        void OnError(const std::string &message) override
        {
            SGLOGI("UploadQueryCallback Error: %{public}s", message.c_str());
        };

    public:
        std::condition_variable queryCond;
        std::mutex queryMutex;
    };

    class UploadAbilityConnection : public AAFwk::AbilityConnectionStub {
    public:
        std::string eventToJson(const SecurityCollector::SecurityEvent &event)
        {
            nlohmann::json jsonEvent;
            jsonEvent["eventId"] = event.GetEventId();
            jsonEvent["version"] = event.GetVersion();
            jsonEvent["content"] = event.GetContent();
            return jsonEvent.dump();
        }
        void OnAbilityConnectDone(const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject,
                                  int resultCode) override
        {
            std::vector<SecurityCollector::SecurityEvent> events = UploadManager::GetInstance().GetHsdrData();
            MessageParcel data;
            MessageParcel reply;
            if (!data.WriteInterfaceToken(std::u16string(u"OHOS.Security.HSDR.UploadEvents"))) {
                SGLOGE("WriteInterfaceToken failed");
                return;
            }
            if (!data.WriteInt32(events.size())) {
                SGLOGE("failed to WriteInt32 for parcelable vector size");
                return;
            }
            for (const auto &event : events) {
                SGLOGI("Write to HSDR:  %{public}s ", eventToJson(event).c_str());
                if (!data.WriteString16(Str8ToStr16(std::to_string(event.GetEventId())))) {
                    return;
                }
                if (!data.WriteString16(Str8ToStr16(event.GetVersion()))) {
                    return;
                }
                SGLOGI("event.GetContent():  %{public}s ", event.GetContent().c_str());
                if (!data.WriteString16(Str8ToStr16(event.GetContent()))) {
                    return;
                }
            }
            MessageOption option(MessageOption::TF_SYNC);
            int32_t ret = remoteObject->SendRequest(1, data, reply, option);
            if (ret != 0) {
                SGLOGE("SendRequest Failed: %{public}d", ret);
                return;
            }
            ret = reply.ReadInt32();
            if (ret != 0) {
                UploadManager::GetInstance().SetUploadStatus(ret);
                std::u16string retString = reply.ReadString16();
                SGLOGE("Reply: failed  %{public}d: %{public}s", ret, Str16ToStr8(retString).c_str());
                return;
            }
        }
        void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int) override {}
    };

    std::unordered_map<int64_t, std::shared_ptr<SecurityGuardSubscriber>> sgSubscribeMap_{};
};
}  // namespace OHOS::Security::SecurityGuard
#endif  // SECURITY_GUARD_REAL_TIME_DETECT_SERVICE_H