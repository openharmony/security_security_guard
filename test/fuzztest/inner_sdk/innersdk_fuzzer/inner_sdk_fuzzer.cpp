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

#include "inner_sdk_fuzzer.h"

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
#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
#include "risk_analysis_manager_callback_service.h"
#include "risk_analysis_manager_callback_stub.h"
#include "risk_analysis_manager_callback.h"
#include "risk_analysis_manager_proxy.h"
#endif
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

#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
class MockRiskAnalysisManagerCallbackStub : public RiskAnalysisManagerCallbackStub {
public:
    MockRiskAnalysisManagerCallbackStub() = default;
    ~MockRiskAnalysisManagerCallbackStub() override = default;
    int32_t ResponseSecurityModelResult(const std::string &devId, uint32_t modelId, std::string &result) override
    {
        return 0;
    };
};
#endif
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


void DataCollectManagerFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    EventSubscribeClient client {};
    auto mute = std::make_shared<Security::SecurityGuard::EventMuteFilter>();
    mute->eventId = fdp.ConsumeIntegral<int64_t>();
    mute->type = fdp.ConsumeIntegral<int64_t>();
    mute->isInclude = fdp.ConsumeIntegral<bool>();
    mute->mutes.insert(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    client.AddFilter(mute);
    client.RemoveFilter(mute);
    auto func = [] (std::string &devId, std::string &riskData, uint32_t status,
        const std::string &errMsg)-> int32_t {
        return 0;
    };
    std::string string = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    std::string string1 = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    DataCollectManager::GetInstance().RequestSecurityEventInfo(string, string1, func);
}

#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
void RiskAnalysisManagerCallbackStubFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    MockRiskAnalysisManagerCallbackStub stub;
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = fdp.ConsumeIntegral<uint32_t>();
    std::string string(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    datas.WriteInterfaceToken(IRiskAnalysisManagerCallback::GetDescriptor());
    datas.WriteUint32(fdp.ConsumeIntegral<uint32_t>());
    datas.WriteString(string);
    datas.WriteString(string);
    stub.OnRemoteRequest(code, datas, reply, option);

    ResultCallback callback;
    RiskAnalysisManagerCallbackService service(callback);
    service.ResponseSecurityModelResult(string, code, string);
    service.callback_ = TestResultCallback;
    service.ResponseSecurityModelResult(string, code, string);
}

void RiskAnalysisManagerProxyFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    ResultCallback func = [] (const std::string &devId, uint32_t modelId, const std::string &result) -> int32_t {
        return 0;
    };
    sptr<RiskAnalysisManagerCallbackService> callback = new (std::nothrow) RiskAnalysisManagerCallbackService(func);
    uint32_t uint32 = fdp.ConsumeIntegral<uint32_t>();
    std::string string(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    RiskAnalysisManagerProxy proxy{obj};
    proxy.RequestSecurityModelResult(string, uint32, string, callback);
}
#endif
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
    OHOS::RiskAnalysisManagerCallbackStubFuzzTest(data, size);
    OHOS::RiskAnalysisManagerProxyFuzzTest(data, size);
#endif
    return 0;
}