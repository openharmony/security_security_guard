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

#include "data_collect_fuzzer.h"

#include <string>

#include "securec.h"
#include <string_ex.h>

#define private public
#define protected public
#include "event_define.h"
#include "acquire_data_subscribe_manager.h"
#include "acquire_data_callback_proxy.h"
#include "data_collect_manager_callback_proxy.h"
#include "data_collect_manager_service.h"
#include "data_collect_manager_stub.h"
#include "security_event_query_callback_proxy.h"
#include "database_helper.h"
#include "database_manager.h"
#include "database.h"
#include "rdb_event_store_callback.h"
#include "risk_event_rdb_helper.h"
#include "store_define.h"
#undef private
#undef prtected

using namespace OHOS::Security::SecurityGuard;

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

bool AcquireDataSubscribeManagerFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return false;
    }
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data + offset));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    Security::SecurityCollector::Event event{eventId, string, string, string};
    Security::SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{event};
    AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj);
    AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId, obj);
    AcquireDataSubscribeManager::GetInstance().BatchPublish(event);
    AcquireDataSubscribeManager::GetInstance().SubscribeSc(eventId, obj);
    AcquireDataSubscribeManager::GetInstance().UnSubscribeSc(eventId);
    AcquireDataSubscribeManager::GetInstance().SubscribeScInSg(eventId, obj);
    AcquireDataSubscribeManager::GetInstance().SubscribeScInSc(eventId, obj);
    SecurityEventFilter subscribeMute {};
    subscribeMute.filter_.eventId = eventId;
    subscribeMute.filter_.eventGroup = string;
    subscribeMute.filter_.mutes.emplace_back(string);
    AcquireDataSubscribeManager::GetInstance().InsertSubscribeMute(subscribeMute, obj, string);
    AcquireDataSubscribeManager::GetInstance().RemoveSubscribeMute(subscribeMute, obj, string);
    AcquireDataSubscribeManager::GetInstance().BatchUpload(obj, std::vector<Security::SecurityCollector::Event>{event});
    AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecordOnRemoteDied(obj);
    return true;
}

bool AcquireDataCallbackProxyFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return false;
    }
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    Security::SecurityCollector::Event event{eventId, string, string, string};
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    AcquireDataCallbackProxy proxy{obj};
    proxy.OnNotify({event});
    return true;
}

bool DataCollectManagerCallbackProxyFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return false;
    }
    size_t offset = 0;
    uint32_t status = *(reinterpret_cast<const uint32_t *>(data));
    offset += sizeof(uint32_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    DataCollectManagerCallbackProxy proxy{obj};
    proxy.ResponseRiskData(string, string, status);
    return true;
}

bool DataCollectManagerServiceFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t) + sizeof(int64_t)) {
        return false;
    }
    size_t offset = 0;
    int fd = static_cast<int32_t>(size);
    offset += sizeof(int32_t);
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    std::vector<std::u16string> args{Str8ToStr16(string)};
    Security::SecurityCollector::SecurityEventRuler ruler{eventId};
    Security::SecurityCollector::Event event{eventId, string, string, string};
    Security::SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{event};
    SecurityConfigUpdateInfo updateInfo{0};
    RequestCondition condition;
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    auto proxy = iface_cast<ISecurityEventQueryCallback>(obj);
    sptr<IRemoteObject> callback(new (std::nothrow) MockRemoteObject());
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, false);
    service.Dump(fd, args);
    service.RequestDataSubmit(eventId, string, string, string);
    service.OnAddSystemAbility(fd, string);
    service.OnRemoveSystemAbility(fd, string);
    service.QueryEventByRuler(proxy, ruler);
    service.CollectorStart(subscribeInfo, callback);
    service.CollectorStop(subscribeInfo, callback);
    service.ConfigUpdate(updateInfo);
    service.WriteRemoteFileToLocal(updateInfo, string);
    DataCollectManagerService::GetSecEventsFromConditions(condition);
    return true;
}

bool SecurityEventQueryCallbackProxyFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return false;
    }
    size_t offset = 0;
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    SecurityEventQueryCallbackProxy proxy{obj};
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    Security::SecurityCollector::SecurityEvent event{eventId};
    std::vector<Security::SecurityCollector::SecurityEvent> events{event};
    proxy.OnQuery(events);
    proxy.OnComplete();
    proxy.OnError(string);
    return true;
}

bool DatabaseHelperFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return false;
    }
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    std::vector<int64_t> eventIds{eventId};
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    DatabaseHelper helper{string};
    SecEvent event = {
        .eventId = eventId,
        .version = string,
    };
    std::vector<SecEvent> events{event};
    NativeRdb::ValuesBucket values{};
    NativeRdb::RdbPredicates predicates{string};
    helper.Init();
    helper.InsertEvent(event);
    helper.QueryAllEvent(events);
    helper.QueryRecentEventByEventId(eventId, event);
    helper.QueryRecentEventByEventId(eventIds, events);
    helper.QueryEventByEventId(eventId, events);
    helper.QueryEventByEventId(eventIds, events);
    helper.QueryEventByEventIdAndDate(eventIds, events, string, string);
    helper.QueryEventByEventType(eventId, events);
    helper.QueryEventByLevel(eventId, events);
    helper.QueryEventByOwner(string, events);
    helper.CountAllEvent();
    helper.CountEventByEventId(eventId);
    helper.DeleteOldEventByEventId(eventId, eventId);
    helper.DeleteAllEventByEventId(eventId);
    helper.FlushAllEvent();
    helper.QueryEventBase(predicates, events);
    helper.CreateTable();
    helper.SetValuesBucket(event, values);
    helper.Release();
    return true;
}

bool DatabaseManagerFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t) + sizeof(int64_t)) {
        return false;
    }
    size_t offset = 0;
    uint32_t source = *(reinterpret_cast<const uint32_t *>(data));
    offset += sizeof(uint32_t);
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    SecEvent event = {
        .eventId = eventId,
        .version = string,
    };
    std::vector<SecEvent> events{event};
    int32_t tmp = static_cast<int32_t>(size);
    std::vector<int64_t> eventIds{eventId};
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    DatabaseManager::GetInstance().InsertEvent(source, event);
    DatabaseManager::GetInstance().QueryAllEvent(string, events);
    DatabaseManager::GetInstance().QueryRecentEventByEventId(eventId, event);
    DatabaseManager::GetInstance().QueryRecentEventByEventId(string, eventIds, events);
    DatabaseManager::GetInstance().QueryEventByEventIdAndDate(string, eventIds, events, string, string);
    DatabaseManager::GetInstance().QueryEventByEventId(eventId, events);
    DatabaseManager::GetInstance().QueryEventByEventId(string, eventIds, events);
    DatabaseManager::GetInstance().QueryEventByEventType(string, tmp, events);
    DatabaseManager::GetInstance().QueryEventByLevel(string, tmp, events);
    DatabaseManager::GetInstance().QueryEventByOwner(string, string, events);
    DatabaseManager::GetInstance().CountAllEvent(string);
    DatabaseManager::GetInstance().CountEventByEventId(eventId);
    DatabaseManager::GetInstance().DeleteOldEventByEventId(eventId, eventId);
    DatabaseManager::GetInstance().DeleteAllEventByEventId(eventId);
    DatabaseManager::GetInstance().SubscribeDb(eventIds, nullptr);
    DatabaseManager::GetInstance().UnSubscribeDb(eventIds, nullptr);
    return true;
}

bool DatabaseFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t) + sizeof(int64_t)) {
        return false;
    }
    size_t offset = 0;
    Database database{};
    int32_t int32 = static_cast<int32_t>(size);
    offset += sizeof(int32_t);
    int64_t int64 = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char *>(data + offset), size - offset);
    NativeRdb::RdbStoreConfig config{string};
    NativeRdb::ValuesBucket value{};
    NativeRdb::AbsRdbPredicates predicates{string};
    std::vector<NativeRdb::ValuesBucket> values{value};
    std::vector<std::string> columns{string};
    database.Insert(int64, string, value);
    database.BatchInsert(int64, string, values);
    database.Update(int32, value, predicates);
    database.Delete(int32, predicates);
    database.Query(predicates, columns);
    database.ExecuteSql(string);
    database.ExecuteAndGetLong(int64, string);
    database.Count(int64, predicates);
    database.BeginTransaction();
    database.RollBack();
    database.Commit();
    return true;
}

void RiskEventRdbHelperFuzzTest()
{
    Security::SecurityGuard::RiskEventRdbHelper::GetInstance().Init();
}
}  // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::RiskEventRdbHelperFuzzTest();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::AcquireDataSubscribeManagerFuzzTest(data, size);
    OHOS::DataCollectManagerCallbackProxyFuzzTest(data, size);
    OHOS::DataCollectManagerServiceFuzzTest(data, size);
    OHOS::SecurityEventQueryCallbackProxyFuzzTest(data, size);
    OHOS::DatabaseHelperFuzzTest(data, size);
    OHOS::DatabaseManagerFuzzTest(data, size);
    OHOS::DatabaseFuzzTest(data, size);
    return 0;
}