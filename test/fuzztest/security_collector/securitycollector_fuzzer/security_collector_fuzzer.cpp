/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "security_collector_fuzzer.h"

#include <string>

#include "securec.h"

#define private public
#define protected public
#include "collector_cfg_marshalling.h"
#include "data_collection.h"
#include "lib_loader.h"
#include "security_collector_manager_callback_proxy.h"
#include "security_collector_manager_service.h"
#include "security_collector_manager_stub.h"
#include "security_collector_run_manager.h"
#include "security_collector_subscriber_manager.h"
#include "security_collector_subscriber.h"
#include "event_define.h"
#undef private
#undef protected

using namespace OHOS::Security::SecurityCollector;

namespace OHOS {
class MockRemoteObject final : public IRemoteObject {
public:
    MockRemoteObject() : IRemoteObject(u"")
    {
    }
    int32_t GetObjectRefCount() { return 0; };
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) { return 0; };
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; };
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; };
    int Dump(int fd, const std::vector<std::u16string> &args) { return 0; };
};

void DataCollectionFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    SecurityCollectorSubscribeInfo subseciberInfo{};
    auto subscriber = std::make_shared<SecurityCollectorSubscriber>(string, subseciberInfo, nullptr,
        [] (const std::string &appName, const sptr<IRemoteObject> &remote, const Event &event) {});
    auto collectorListenner = std::make_shared<SecurityCollectorRunManager::CollectorListenner>(subscriber);
    std::vector<int64_t> eventIds{eventId};
    int32_t collectorType = static_cast<int32_t>(size);
    SecurityEventRuler ruler{};
    std::vector<SecurityEventRuler> rulers{ruler};
    std::vector<SecurityEvent> events{};
    std::ifstream stream{string};
    DataCollection::GetInstance().StartCollectors(eventIds, collectorListenner);
    DataCollection::GetInstance().StopCollectors(eventIds);
    DataCollection::GetInstance().GetCollectorType(eventId, collectorType);
    DataCollection::GetInstance().QuerySecurityEvent(rulers, events);
    DataCollection::GetInstance().LoadCollector(eventId, string, collectorListenner);
    DataCollection::GetInstance().LoadCollector(string, ruler, events);
    DataCollection::GetInstance().GetCollectorPath(eventId, string);
    DataCollection::GetInstance().CheckFileStream(stream);
    DataCollection::GetInstance().IsCollectorStarted(eventId);
}

void LibLoaderFuzzTest(const uint8_t* data, size_t size)
{
    std::string string(reinterpret_cast<const char*>(data), size);
    LibLoader loader{string};
    loader.LoadLib();
    loader.CallGetCollector();
    loader.UnLoadLib();
}

void SecurityCollectorManagerCallbackProxyFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    Security::SecurityCollector::Event event{eventId, string, string, string};
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    SecurityCollectorManagerCallbackProxy proxy{obj};
    proxy.OnNotify(event);
}

void SecurityCollectorManagerServiceFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    SecurityCollectorManagerService service(SECURITY_COLLECTOR_MANAGER_SA_ID, false);
    Security::SecurityCollector::Event event{eventId, string, string, string};
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    SecurityEventRuler ruler{};
    std::vector<SecurityEventRuler> rulers{ruler};
    SecurityCollectorSubscribeInfo subscribeInfo{event};
    ScSubscribeEvent scEvent{};
    ScUnsubscribeEvent scuEvent{};
    scEvent.eventId = eventId;
    std::vector<SecurityEvent> events{};
    service.Subscribe(subscribeInfo, obj);
    service.Unsubscribe(obj);
    service.CollectorStop(subscribeInfo, obj);
    service.CollectorStart(subscribeInfo, obj);
    service.QuerySecurityEvent(rulers, events);
    SecurityCollectorManagerService::ReportScSubscribeEvent(scEvent);
    SecurityCollectorManagerService::ReportScUnsubscribeEvent(scuEvent);
    SecurityCollectorManagerService::GetAppName();
    SecurityCollectorManagerService::HasPermission(string);
    SecurityCollectorEventMuteFilter fil {};
    fil.eventId = eventId;
    fil.mutes.emplace_back(string);
    SecurityCollectorEventFilter filter(fil);
    service.Mute(filter, string);
    service.Unmute(filter, string);
    service.CleanSubscriber(obj);
    service.ExecuteOnNotifyByTask(obj, event);
}

void SecurityCollectorRunManagerFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    Security::SecurityCollector::Event event{eventId, string, string, string};
    SecurityCollectorSubscribeInfo subscriberInfo{};
    auto subscriber = std::make_shared<SecurityCollectorSubscriber>(string, subscriberInfo, nullptr,
        [] (const std::string &appName, const sptr<IRemoteObject> &remote, const Event &event) {});
    SecurityCollectorRunManager manager;
    manager.StartCollector(subscriber);
    manager.StopCollector(subscriber);
    SecurityCollectorRunManager::CollectorListenner listener{subscriber};
    listener.GetExtraInfo();
    listener.OnNotify(event);
}

void SecurityCollectorSubscriberManagerFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    SecurityCollectorSubscribeInfo subscriberInfo{};
    Security::SecurityCollector::Event event{eventId, string, string, string};
    auto subscriber = std::make_shared<SecurityCollectorSubscriber>(string, subscriberInfo, nullptr,
        [] (const std::string &appName, const sptr<IRemoteObject> &remote, const Event &event) {});
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    SecurityCollectorSubscriberManager::GetInstance().SubscribeCollector(subscriber);
    SecurityCollectorSubscriberManager::GetInstance().UnsubscribeCollector(obj);
    SecurityCollectorSubscriberManager::GetInstance().FindEventIds(obj);
    SecurityCollectorSubscriberManager::GetInstance().GetAppSubscribeCount(string);
    SecurityCollectorSubscriberManager::GetInstance().GetAppSubscribeCount(string, eventId);
    SecurityCollectorSubscriberManager::GetInstance().NotifySubscriber(event);
    SecurityCollectorSubscriberManager::CollectorListenner listener{subscriber};
    listener.GetExtraInfo();
    listener.OnNotify(event);
}

class TestCollector : public ICollector {
public:
    int Start(std::shared_ptr<ICollectorFwk> api) override {return 0;};
    int Stop()  override {return 0;};
};


void SecurityCollectorICollectorFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    TestCollector collector;
    SecurityCollectorEventMuteFilter collectorFilter {};
    collectorFilter.eventId = eventId;
    collectorFilter.mutes.emplace_back(string);
    SecurityEvent event {};
    event.eventId_ = eventId;
    event.content_ = string;
    event.version_ = string;
    event.timestamp_ = string;

    std::vector<SecurityEvent> eventIds {};
    eventIds.emplace_back(event);
    SecurityEventRuler ruler;
    ruler.eventId_ = eventId;
    ruler.beginTime_ = string;
    ruler.endTime_ = string;
    ruler.param_ = string;
    collector.IsStartWithSub();
    collector.Mute(collectorFilter, string);
    collector.Unmute(collectorFilter, string);
    collector.Query(ruler, eventIds);
    collector.Subscribe(eventId);
    collector.Unsubscribe(eventId);
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::DataCollectionFuzzTest(data, size);
    OHOS::LibLoaderFuzzTest(data, size);
    OHOS::SecurityCollectorManagerCallbackProxyFuzzTest(data, size);
    OHOS::SecurityCollectorManagerServiceFuzzTest(data, size);
    OHOS::SecurityCollectorRunManagerFuzzTest(data, size);
    OHOS::SecurityCollectorSubscriberManagerFuzzTest(data, size);
    return 0;
}
