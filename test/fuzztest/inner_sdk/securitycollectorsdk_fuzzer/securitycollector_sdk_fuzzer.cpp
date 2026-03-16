/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "securitycollector_sdk_fuzzer.h"

#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "securec.h"

#define private public
#define protected public
#include "data_collect_manager.h"
#include "event_subscribe_client.h"
#include "acquire_data_manager_callback_service.h"
#include "acquire_data_manager_callback_stub.h"
#include "data_collect_manager_callback_service.h"
#include "data_collect_manager_callback_stub.h"
#include "data_collect_manager_idl_proxy.h"
#include "collector_manager.h"
#include "security_collector_manager_callback_stub.h"
#include "security_collector_manager_proxy.h"
#include "security_collector_subscribe_info.h"
#include "security_event.h"
#include "security_event_ruler.h"
#include "security_event_query_callback_service.h"
#undef private
#undef protected

using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityCollector;
namespace {
    constexpr int MAX_STRING_SIZE = 1024;
    OHOS::sptr<OHOS::IPCObjectProxy::DeathRecipient> ret {};
}
namespace OHOS {
class MockCollectorSubscriber : public ICollectorSubscriber {
public:
    explicit MockCollectorSubscriber(const Event &event) : ICollectorSubscriber(event) {};
    int32_t OnNotify(const Event &event) override { return 0; };
};

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

class MockAcquireDataManagerCallbackStub : public AcquireDataManagerCallbackStub {
public:
    explicit MockAcquireDataManagerCallbackStub() = default;
    ~MockAcquireDataManagerCallbackStub() override = default;
    int32_t OnNotify(const std::vector<Security::SecurityCollector::Event> &events) override { return 0; };
};


class MockSecurityCollectorManagerCallbackStub : public SecurityCollectorManagerCallbackStub {
public:
    MockSecurityCollectorManagerCallbackStub() = default;
    ~MockSecurityCollectorManagerCallbackStub() override = default;

    int32_t OnNotify(const Event &event) override { return 0; };
};

class MockDataCollectManagerCallbackStub : public DataCollectManagerCallbackStub {
public:
    MockDataCollectManagerCallbackStub() = default;
    ~MockDataCollectManagerCallbackStub() override = default;

    int32_t ResponseRiskData(std::string &devId, std::string &riskData, uint32_t status,
        const std::string& errMsg = "") override { return 0; };
};

class MockSecurityEventQueryCallback : public SecurityEventQueryCallback {
public:
    MockSecurityEventQueryCallback() = default;
    ~MockSecurityEventQueryCallback() override = default;
    void OnQuery(const std::vector<SecurityEvent> &events) override {};
    void OnComplete() override {};
    void OnError(const std::string &message) override {};
};

int32_t TestRequestRiskDataCallback(std::string &, std::string &, uint32_t, const std::string &)
{
    return 0;
}

int32_t TestResultCallback(const std::string &devId, uint32_t modelId, const std::string &result)
{
    return 0;
}

void SecurityCollectorManagerCallbackStubFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t) + sizeof(uint32_t)) {
        return;
    }
    size_t offset = 0;
    MockSecurityCollectorManagerCallbackStub stub;
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = *(reinterpret_cast<const uint32_t *>(data + offset));
    offset += sizeof(uint32_t);
    uint32_t uint32 = *(reinterpret_cast<const uint32_t *>(data + offset));
    offset += sizeof(uint32_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    datas.WriteInterfaceToken(ISecurityCollectorManagerCallback::GetDescriptor());
    datas.WriteUint32(uint32);
    datas.WriteString(string);
    datas.WriteString(string);
    datas.WriteString(string);
    stub.OnRemoteRequest(code, datas, reply, option);
}

void SecurityCollectorManagerProxyFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<Security::SecurityCollector::SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) Security::SecurityCollector::SecurityCollectorManagerCallbackService(nullptr);
    std::string string(reinterpret_cast<const char *>(data), size);
    int64_t int64 = *(reinterpret_cast<const int64_t *>(data));
    SecurityCollectorSubscribeInfo subscribeInfo({int64, string, string, string});
    SecurityCollectorManagerProxy proxy{obj};
    std::vector<SecurityEventRuler> rulers{};
    std::vector<SecurityEvent> events{};
    proxy.Subscribe(subscribeInfo, callback);
    proxy.Unsubscribe(callback);
    proxy.CollectorStart(subscribeInfo, callback);
    proxy.CollectorStop(subscribeInfo, callback);
    proxy.QuerySecurityEvent(rulers, events);
}

void SecurityCollectorSubscribeInfoFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    std::string string(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    int64_t int64 = fdp.ConsumeIntegral<int64_t>();
    SecurityCollectorSubscribeInfo info;
    Parcel parcel;
    info.Marshalling(parcel);
    info.Unmarshalling(parcel);
    info.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    info.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    info.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    parcel.WriteInt64(int64);
    info.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    info.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    parcel.WriteString(string);
    info.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    parcel.WriteString(string);
    parcel.WriteString(string);
    info.ReadFromParcel(parcel);

    info.Unmarshalling(parcel);
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::SecurityCollectorManagerCallbackStubFuzzTest(data, size);
    OHOS::SecurityCollectorManagerProxyFuzzTest(data, size);
    OHOS::SecurityCollectorSubscribeInfoFuzzTest(data, size);
    return 0;
}