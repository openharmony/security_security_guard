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

#include "inner_api_collector_test.h"

#include "gmock/gmock.h"

#include "security_guard_define.h"
#include "security_guard_log.h"
#define private public
#define protected public
#include "acquire_data_manager_callback_service.h"
#include "acquire_data_manager_callback_stub.h"
#include "data_collect_manager_callback_service.h"
#include "data_collect_manager_callback_stub.h"
#include "data_collect_manager_idl_proxy.h"
#include "data_collect_manager.h"
#include "risk_analysis_manager_callback_service.h"
#include "risk_analysis_manager_callback_stub.h"
#include "risk_analysis_manager_callback.h"
#include "risk_analysis_manager_proxy.h"
#include "collector_manager.h"
#include "security_collector_manager_callback_stub.h"
#include "security_collector_manager_proxy.h"
#include "security_collector_subscribe_info.h"
#include "security_event.h"
#include "security_event_ruler.h"
#include "security_event_query_callback_service.h"
#include "security_event_query_callback_stub.h"
#include "security_event_query_callback.h"
#undef private
#undef protected

using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityCollector;

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
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; };
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; };
    int Dump(int fd, const std::vector<std::u16string> &args) { return 0; };
};

class MockAcquireDataManagerCallbackStub : public AcquireDataManagerCallbackStub {
public:
    explicit MockAcquireDataManagerCallbackStub() = default;
    ~MockAcquireDataManagerCallbackStub() override = default;
    int32_t OnNotify(const std::vector<Security::SecurityCollector::Event> &events) override { return 0; };
};

class MockRiskAnalysisManagerCallbackStub : public RiskAnalysisManagerCallbackStub {
public:
    MockRiskAnalysisManagerCallbackStub() = default;
    ~MockRiskAnalysisManagerCallbackStub() override = default;
    int32_t ResponseSecurityModelResult(const std::string &devId, uint32_t modelId, std::string &result) override
    {
        return 0;
    };
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

class MockSecurityEventQueryCallbackStub : public SecurityEventQueryCallbackStub {
public:
    MockSecurityEventQueryCallbackStub() = default;
    ~MockSecurityEventQueryCallbackStub() override = default;
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
}

namespace OHOS::Security::SecurityGuardTest {
void InnerApiCollectorTest::SetUpTestCase()
{
}

void InnerApiCollectorTest::TearDownTestCase()
{
}

void InnerApiCollectorTest::SetUp()
{
}

void InnerApiCollectorTest::TearDown()
{
}

HWTEST_F(InnerApiCollectorTest, AcquireDataManagerTest001, testing::ext::TestSize.Level1)
{
    Security::SecurityCollector::Event event;
    auto subscriber = std::make_shared<MockCollectorSubscriber>(event);
    int ret = DataCollectManager::GetInstance().Subscribe(subscriber);
    EXPECT_FALSE(ret == SUCCESS);
    ret = DataCollectManager::GetInstance().Unsubscribe(subscriber);
    EXPECT_TRUE(ret == BAD_PARAM);
    DataCollectManager::GetInstance().HandleDecipient();

    AcquireDataManagerCallbackService service;
    ret = service.OnNotify({event});
    EXPECT_TRUE(ret == FAILED);

    service.RegistCallBack(
        [] (const Security::SecurityCollector::Event &event) {}
    );
    ret = service.OnNotify({event});
    EXPECT_TRUE(ret == SUCCESS);
}

HWTEST_F(InnerApiCollectorTest, AcquireDataManagerCallbackStubTest001, testing::ext::TestSize.Level1)
{
    MockAcquireDataManagerCallbackStub stub;
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    int ret = stub.OnRemoteRequest(0, datas, reply, option);
    EXPECT_TRUE(ret == NO_PERMISSION);
    int64_t int64 = 0;
    std::string string = "test";
    datas.WriteInterfaceToken(AcquireDataManagerCallbackStub::GetDescriptor());
    ret = stub.OnRemoteRequest(0, datas, reply, option);
    EXPECT_FALSE(ret == SUCCESS);
    datas.WriteInterfaceToken(AcquireDataManagerCallbackStub::GetDescriptor());
    datas.WriteInt64(int64);
    datas.WriteString(string);
    datas.WriteString(string);
    datas.WriteString(string);
    ret = stub.OnRemoteRequest(AcquireDataManagerCallbackStub::CMD_DATA_SUBSCRIBE_CALLBACK, datas, reply, option);
    EXPECT_TRUE(ret == SUCCESS);
}

HWTEST_F(InnerApiCollectorTest, RiskAnalysisManagerCallbackServiceTest001, testing::ext::TestSize.Level1)
{
    MockRiskAnalysisManagerCallbackStub stub;
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = 0;
    std::string string = "test";
    int ret = stub.OnRemoteRequest(code, datas, reply, option);
    EXPECT_TRUE(ret == NO_PERMISSION);
    datas.WriteInterfaceToken(IRiskAnalysisManagerCallback::GetDescriptor());
    ret = stub.OnRemoteRequest(code, datas, reply, option);
    EXPECT_FALSE(ret == SUCCESS);
    datas.WriteInterfaceToken(IRiskAnalysisManagerCallback::GetDescriptor());
    datas.WriteUint32(0);
    datas.WriteString(string);
    ret = stub.OnRemoteRequest(RiskAnalysisManagerCallbackStub::CMD_SET_SECURITY_MODEL_RESULT,
        datas, reply, option);
    EXPECT_TRUE(ret == SUCCESS);
    ResultCallback callback;
    RiskAnalysisManagerCallbackService service(callback);
    ret = service.ResponseSecurityModelResult(string, code, string);
    EXPECT_TRUE(ret == SUCCESS);
    service.callback_ = TestResultCallback;
    ret = service.ResponseSecurityModelResult(string, code, string);
    EXPECT_TRUE(ret == SUCCESS);
}

HWTEST_F(InnerApiCollectorTest, RiskAnalysisManagerProxyTest001, testing::ext::TestSize.Level1)
{
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    ResultCallback func = [] (const std::string &devId, uint32_t modelId, const std::string &result) -> int32_t {
        return 0;
    };
    sptr<RiskAnalysisManagerCallbackService> callback = new (std::nothrow) RiskAnalysisManagerCallbackService(func);
    uint32_t uint32 = 0;
    std::string string = "test";
    RiskAnalysisManagerProxy proxy{obj};
    int ret = proxy.RequestSecurityModelResult(string, uint32, string, callback);
    EXPECT_TRUE(ret == SUCCESS);
    ret = proxy.SetModelState(uint32, true);
    EXPECT_TRUE(ret == SUCCESS);
}

HWTEST_F(InnerApiCollectorTest, CollectorManagerTest001, testing::ext::TestSize.Level1)
{
    Security::SecurityCollector::Event event;
    auto subscriber = std::make_shared<MockCollectorSubscriber>(event);
    std::vector<SecurityEventRuler> rulers{};
    std::vector<SecurityEvent> events{};
    SecurityCollectorSubscribeInfo subscribeInfo{};
    int ret = CollectorManager::GetInstance().Subscribe(subscriber);
    EXPECT_FALSE(ret == SUCCESS);
    ret = CollectorManager::GetInstance().Unsubscribe(subscriber);
    EXPECT_TRUE(ret == BAD_PARAM);
    ret = CollectorManager::GetInstance().QuerySecurityEvent(rulers, events);
    EXPECT_FALSE(ret == SUCCESS);
    ret = CollectorManager::GetInstance().CollectorStart(subscribeInfo);
    EXPECT_FALSE(ret == SUCCESS);
    ret = CollectorManager::GetInstance().CollectorStop(subscribeInfo);
    EXPECT_FALSE(ret == SUCCESS);

    CollectorManager manager;
    sptr<Security::SecurityCollector::SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) Security::SecurityCollector::SecurityCollectorManagerCallbackService(nullptr);
    manager.eventListeners_[subscriber] = callback;
    ret = manager.Subscribe(nullptr);
    EXPECT_TRUE(ret == BAD_PARAM);
    ret = manager.Subscribe(subscriber);
    EXPECT_FALSE(ret == SUCCESS);
    ret = manager.Unsubscribe(nullptr);
    EXPECT_TRUE(ret == BAD_PARAM);
    ret = manager.Unsubscribe(subscriber);
    EXPECT_FALSE(ret == SUCCESS);
}

HWTEST_F(InnerApiCollectorTest, DataCollectManagerCallbackServiceTest001, testing::ext::TestSize.Level1)
{
    MockDataCollectManagerCallbackStub stub;
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    uint32_t uint32 = 0;
    std::string string = "test";
    datas.WriteInterfaceToken(IDataCollectManagerCallback::GetDescriptor());
    datas.WriteString(string);
    datas.WriteUint32(uint32);
    datas.WriteString(string);
    int ret = stub.OnRemoteRequest(DataCollectManagerCallbackStub::CMD_SET_REQUEST_DATA, datas, reply, option);
    EXPECT_TRUE(ret == SUCCESS);
    ret = stub.OnRemoteRequest(0, datas, reply, option);
    EXPECT_FALSE(ret == SUCCESS);
    RequestRiskDataCallback callback;
    DataCollectManagerCallbackService service(callback);
    ret = service.ResponseRiskData(string, string, uint32, string);
    EXPECT_TRUE(ret == NULL_OBJECT);
    service.callback_ = TestRequestRiskDataCallback;
    ret = service.ResponseRiskData(string, string, uint32, string);
    EXPECT_TRUE(ret == SUCCESS);
}

HWTEST_F(InnerApiCollectorTest, DataCollectManagerTest001, testing::ext::TestSize.Level1)
{
    DataCollectManager manager;
    std::vector<SecurityEventRuler> rulers;
    std::shared_ptr<MockSecurityEventQueryCallback> callback = std::make_shared<MockSecurityEventQueryCallback>();
    int ret = manager.QuerySecurityEvent(rulers, callback);
    EXPECT_TRUE(ret != SUCCESS);
}

HWTEST_F(InnerApiCollectorTest, SecurityCollectorManagerCallbackStubTest001, testing::ext::TestSize.Level1)
{
    MockSecurityCollectorManagerCallbackStub stub;
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = 0;
    int64_t eventId = 0;
    std::string string = "test";
    std::vector<std::string> vec ={{"1111111111"}, "222222222"};
    int ret = stub.OnRemoteRequest(code, datas, reply, option);
    EXPECT_TRUE(ret == NO_PERMISSION);
    datas.WriteInterfaceToken(ISecurityCollectorManagerCallback::GetDescriptor());
    ret = stub.OnRemoteRequest(code, datas, reply, option);
    EXPECT_FALSE(ret == SUCCESS);
    datas.WriteInterfaceToken(ISecurityCollectorManagerCallback::GetDescriptor());
    datas.WriteInt64(eventId);
    datas.WriteString(string);
    datas.WriteString(string);
    datas.WriteString(string);
    datas.WriteUint32(static_cast<uint32_t>(vec.size()));
    for (auto iter : vec) {
        datas.WriteString(iter);
    }
    ret = stub.OnRemoteRequest(SecurityCollectorManagerCallbackStub::CMD_COLLECTOR_NOTIFY, datas, reply, option);
    EXPECT_TRUE(ret == SUCCESS);
}

HWTEST_F(InnerApiCollectorTest, SecurityCollectorManagerProxyTest001, testing::ext::TestSize.Level1)
{
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<Security::SecurityCollector::SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) Security::SecurityCollector::SecurityCollectorManagerCallbackService(nullptr);
    SecurityCollectorSubscribeInfo subscribeInfo{};
    SecurityCollectorManagerProxy proxy{obj};
    std::vector<SecurityEventRuler> rulers{};
    std::vector<SecurityEvent> events{};
    int ret = proxy.Subscribe(subscribeInfo, callback);
    EXPECT_TRUE(ret == SUCCESS);
    ret = proxy.Unsubscribe(callback);
    EXPECT_TRUE(ret == SUCCESS);
    ret = proxy.CollectorStart(subscribeInfo, callback);
    EXPECT_TRUE(ret == SUCCESS);
    ret = proxy.CollectorStop(subscribeInfo, callback);
    EXPECT_TRUE(ret == SUCCESS);
    ret = proxy.QuerySecurityEvent(rulers, events);
    EXPECT_FALSE(ret == SUCCESS);
}

HWTEST_F(InnerApiCollectorTest, SecurityCollectorSubscribeInfoTest001, testing::ext::TestSize.Level1)
{
    std::string string = "test";
    int64_t int64 = 0;
    SecurityCollectorSubscribeInfo info;
    Parcel parcel;
    bool ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);
    SecurityCollectorSubscribeInfo *retInfo = info.Unmarshalling(parcel);
    EXPECT_FALSE(retInfo == nullptr);
    ret = info.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    ret = info.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    ret = info.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    parcel.WriteInt64(int64);
    ret = info.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    ret = info.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    parcel.WriteString(string);
    ret = info.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    parcel.WriteString(string);
    parcel.WriteString(string);
    parcel.WriteString(string);
    ret = info.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);

    retInfo = info.Unmarshalling(parcel);
    EXPECT_TRUE(retInfo == nullptr);
}

HWTEST_F(InnerApiCollectorTest, SecurityEventTest001, testing::ext::TestSize.Level1)
{
    std::string string = "test";
    int64_t int64 = 0;
    SecurityEvent event;
    Parcel parcel;
    bool ret = event.Marshalling(parcel);
    EXPECT_TRUE(ret);
    SecurityEvent *retEvent = event.Unmarshalling(parcel);
    EXPECT_FALSE(retEvent == nullptr);
    ret = event.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    ret = event.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    ret = event.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    parcel.WriteString(string);
    ret = event.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    parcel.WriteString(string);
    parcel.WriteString(string);
    ret = event.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    retEvent = event.Unmarshalling(parcel);
    EXPECT_TRUE(retEvent == nullptr);
}

HWTEST_F(InnerApiCollectorTest, SecurityEventRulerTest001, testing::ext::TestSize.Level1)
{
    std::string string = "test";
    int64_t int64 = 0;
    SecurityEventRuler ruler;
    Parcel parcel;
    int ret = ruler.Marshalling(parcel);
    EXPECT_TRUE(ret);
    SecurityEventRuler *retRuler = ruler.Unmarshalling(parcel);
    EXPECT_FALSE(retRuler == nullptr);
    ret = ruler.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    ret = ruler.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    ret = ruler.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    parcel.WriteString(string);
    ret = ruler.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    parcel.WriteString(string);
    parcel.WriteString(string);
    ret = ruler.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);

    retRuler = ruler.Unmarshalling(parcel);
    EXPECT_TRUE(retRuler == nullptr);
}

HWTEST_F(InnerApiCollectorTest, SecurityEventQueryCallbackServiceTest001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<MockSecurityEventQueryCallback> callback = std::make_shared<MockSecurityEventQueryCallback>();
    SecurityEventQueryCallbackService service(nullptr);
    std::string message = "message";
    std::vector<SecurityEvent> events;
    service.OnQuery(events);
    EXPECT_EQ(events.size(), 0);
    service.OnComplete();
    service.OnError(message);
    EXPECT_EQ(message, "message");
    SecurityEventQueryCallbackService service2(callback);
    service2.OnQuery(events);
    EXPECT_EQ(events.size(), 0);
    service2.OnComplete();
    service2.OnError(message);
    EXPECT_EQ(message, "message");
}

HWTEST_F(InnerApiCollectorTest, SecurityEventQueryCallbackTest001, testing::ext::TestSize.Level1)
{
    MockSecurityEventQueryCallbackStub stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = stub.OnRemoteRequest(0, data, reply, option);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
    data.WriteInterfaceToken(SecurityEventQueryCallbackStub::GetDescriptor());
    ret = stub.OnRemoteRequest(0, data, reply, option);
    EXPECT_FALSE(ret == SecurityGuard::SUCCESS);

    data.WriteInterfaceToken(SecurityEventQueryCallbackStub::GetDescriptor());
    ret = stub.OnRemoteRequest(SecurityEventQueryCallbackStub::CMD_ON_QUERY, data, reply, option);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);

    data.WriteInterfaceToken(SecurityEventQueryCallbackStub::GetDescriptor());
    data.WriteUint32(1);
    ret = stub.OnRemoteRequest(SecurityEventQueryCallbackStub::CMD_ON_QUERY, data, reply, option);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);

    data.WriteInterfaceToken(SecurityEventQueryCallbackStub::GetDescriptor());
    data.WriteUint32(MAX_QUERY_EVENT_SIZE + 1);
    ret = stub.OnRemoteRequest(SecurityEventQueryCallbackStub::CMD_ON_QUERY, data, reply, option);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);

    data.WriteInterfaceToken(SecurityEventQueryCallbackStub::GetDescriptor());
    ret = stub.OnRemoteRequest(SecurityEventQueryCallbackStub::CMD_ON_COMPLETE, data, reply, option);
    EXPECT_EQ(ret, SecurityGuard::SUCCESS);

    data.WriteInterfaceToken(SecurityEventQueryCallbackStub::GetDescriptor());
    stub.OnRemoteRequest(SecurityEventQueryCallbackStub::CMD_ON_ERROR, data, reply, option);
    EXPECT_EQ(ret, SecurityGuard::SUCCESS);
}

}