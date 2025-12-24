/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "data_collect_manager_service_fuzzer.h"

#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "securec.h"
#include <string_ex.h>

#define private public
#define protected public
#include "event_define.h"
#include "acquire_data_subscribe_manager.h"
#include "acquire_data_callback_proxy.h"
#include "data_collect_manager_callback_proxy.h"
#include "data_collect_manager_service.h"
#include "data_collect_manager_idl_stub.h"
#include "security_event_query_callback_proxy.h"
#include "database_helper.h"
#include "database_manager.h"
#include "database.h"
#include "risk_event_rdb_helper.h"
#include "store_define.h"
#undef private
#undef prtected

using namespace OHOS::Security::SecurityGuard;
namespace {
    constexpr int MAX_STRING_SIZE = 1024;
    OHOS::sptr<OHOS::IPCObjectProxy::DeathRecipient> ret {};
}
namespace OHOS {
class MockRemoteObject final : public IRemoteObject {
public:
    MockRemoteObject() : IRemoteObject(u"")
    {
    }
    int32_t GetObjectRefCount() { return 0; };
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) { return 0; };
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient)
    {
        ret = recipient;
        return true;
    };
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; };
    int Dump(int fd, const std::vector<std::u16string> &args) { return 0; };
};

bool DataCollectManagerServiceFuzzTest(FuzzedDataProvider &fdp)
{
    int64_t eventId = fdp.ConsumeIntegral<int64_t>();
    int64_t type = fdp.ConsumeIntegral<int64_t>();
    std::string string = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    int fd = fdp.ConsumeIntegral<int32_t>();
    std::vector<std::u16string> args{Str8ToStr16(string)};
    Security::SecurityCollector::SecurityEventRuler ruler{eventId};
    Security::SecurityCollector::Event event{eventId, string, string, string};
    Security::SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{event};
    Security::SecurityGuard::EventMuteFilter info {};
    info.eventId = eventId;
    info.type = type;
    info.mutes.insert(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    Security::SecurityGuard::SecurityEventFilter filter(info);
    RequestCondition condition;
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    auto proxy = iface_cast<ISecurityEventQueryCallback>(obj);
    sptr<IRemoteObject> callback(new (std::nothrow) MockRemoteObject());
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, false);
    service.Dump(fd, args);
    service.tokenBucket_.fetch_add(1);
    service.RequestDataSubmit(eventId, string, string, string);
    service.RequestDataSubmitAsync(eventId, string, string, string);
    service.OnAddSystemAbility(fd, string);
    service.OnRemoveSystemAbility(fd, string);
    service.QueryEventByRuler(proxy, ruler);
    service.CollectorStart(subscribeInfo, callback);
    service.CollectorStop(subscribeInfo, callback);
    service.Subscribe(subscribeInfo, callback, fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    service.Unsubscribe(subscribeInfo, callback, fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    service.CreatClient(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE),
        fdp.ConsumeRandomLengthString(MAX_STRING_SIZE), callback);
    service.DestoryClient(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE),
        fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    service.AddFilter(filter, fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    service.RemoveFilter(filter, fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    service.ConfigUpdate(fd, fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    service.WriteRemoteFileToLocal(fd, fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    DataCollectManagerService::GetSecEventsFromConditions(condition);
    service.QuerySecurityEventById({ruler}, callback, "auditGroup");
    return true;
}

bool DataCollectManagerServiceFuzzTest1(FuzzedDataProvider &fdp)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, false);
    sptr<IRemoteObject> callback(new (std::nothrow) MockRemoteObject());
    service.ParseTrustListFile(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    std::string result = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    service.QueryEventConfig(result);
    service.QuerySecurityEventConfig(result);
    std::vector<int64_t> eventIds {};
    eventIds.emplace_back(fdp.ConsumeIntegral<int64_t>());
    service.IsEventGroupHasPermission(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE), eventIds);
    int64_t eventId = fdp.ConsumeIntegral<int64_t>();
    service.Subscribe(eventId, fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    service.Unsubscribe(eventId, fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    service.RequestRiskData(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE),
        fdp.ConsumeRandomLengthString(MAX_STRING_SIZE), callback);
    return true;
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    FuzzedDataProvider fdp(data, size);
    OHOS::DataCollectManagerServiceFuzzTest(fdp);
    OHOS::DataCollectManagerServiceFuzzTest1(fdp);
    return 0;
}