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

#include "acquire_data_subscribe_manager_fuzzer.h"

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
}
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

bool AcquireDataSubscribeManagerFuzzTest(FuzzedDataProvider &fdp)
{
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    Security::SecurityCollector::Event event{fdp.ConsumeIntegral<int64_t>(),
        fdp.ConsumeRandomLengthString(MAX_STRING_SIZE), fdp.ConsumeRandomLengthString(MAX_STRING_SIZE),
        fdp.ConsumeRandomLengthString(MAX_STRING_SIZE)};
    Security::SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{event};
    std::string clientId = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj, clientId);
    AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId, obj, clientId);
    int64_t eventId = fdp.ConsumeIntegral<int64_t>();
    AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(eventId, clientId);
    AcquireDataSubscribeManager::GetInstance().IsFindFlag({clientId}, eventId, clientId);
    AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(eventId, clientId);
    AcquireDataSubscribeManager::GetInstance().PublishEventToSub(event);
    AcquireDataSubscribeManager::GetInstance().SubscribeSc(eventId);
    AcquireDataSubscribeManager::GetInstance().UnSubscribeSc(eventId);
    AcquireDataSubscribeManager::GetInstance().SubscribeScInSg(eventId);
    AcquireDataSubscribeManager::GetInstance().SubscribeScInSc(eventId);
    SecurityEventFilter subscribeMute {};
    subscribeMute.filter_.eventId = fdp.ConsumeIntegral<int64_t>();
    subscribeMute.filter_.mutes.insert(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    AcquireDataSubscribeManager::GetInstance().InsertSubscribeMute(subscribeMute.GetMuteFilter(),
        fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    AcquireDataSubscribeManager::GetInstance().RemoveSubscribeMute(subscribeMute.GetMuteFilter(),
        fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    AcquireDataSubscribeManager::GetInstance().NotifySub(obj, event);
    AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecordOnRemoteDied(obj);
    AcquireDataSubscribeManager::GetInstance().CreatClient(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE),
        fdp.ConsumeRandomLengthString(MAX_STRING_SIZE), obj);
    AcquireDataSubscribeManager::GetInstance().DestoryClient(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE),
        fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    AcquireDataSubscribeManager::GetInstance().InsertMute(subscribeMute.GetMuteFilter(),
        fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    AcquireDataSubscribeManager::GetInstance().RemoveMute(subscribeMute.GetMuteFilter(),
        fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    AcquireDataSubscribeManager::GetInstance().StartClearEventCache();
    AcquireDataSubscribeManager::GetInstance().StopClearEventCache();
    AcquireDataSubscribeManager::GetInstance().GetCurrentClientGroup(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    AcquireDataSubscribeManager::GetInstance().DeInitDeviceId();
    AcquireDataSubscribeManager::GetInstance().UploadEventToStore(event);
    AcquireDataSubscribeManager::GetInstance().UploadEvent(event);
    AcquireDataSubscribeManager::GetInstance().UploadEventTask(event);
    AcquireDataSubscribeManager::GetInstance().SubscriberEventOnSgStart();
    return true;
}

bool AcquireDataSubscribeManagerFuzzTest1(FuzzedDataProvider &fdp)
{
    Security::SecurityCollector::Event event{fdp.ConsumeIntegral<int64_t>(),
        fdp.ConsumeRandomLengthString(MAX_STRING_SIZE), fdp.ConsumeRandomLengthString(MAX_STRING_SIZE),
        fdp.ConsumeRandomLengthString(MAX_STRING_SIZE)};
    AcquireDataSubscribeManager::CollectorListener listener {};
    listener.GetExtraInfo();
    listener.OnNotify(event);
    Security::SecurityCollector::Event eventTmp {};
    eventTmp.content = R"({"test":1})";
    AcquireDataSubscribeManager::GetInstance().UploadEvent(eventTmp);
    AcquireDataSubscribeManager::GetInstance().UploadEvent(event);
    AcquireDataSubscribeManager::GetInstance().StartTokenBucketTask();
    AcquireDataSubscribeManager::GetInstance().StopTokenBucketTask();
    return true;
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    FuzzedDataProvider fdp(data, size);
    OHOS::AcquireDataSubscribeManagerFuzzTest(fdp);
    OHOS::AcquireDataSubscribeManagerFuzzTest1(fdp);
    return 0;
}