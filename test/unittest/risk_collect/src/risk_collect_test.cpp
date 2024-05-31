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

#include "risk_collect_test.h"

#include "gmock/gmock.h"

#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#define private public
#define protected public
#include "config_data_manager.h"
#include "database_manager.h"
#include "uevent_listener_impl.h"
#include "uevent_listener.h"
#include "uevent_notify.h"
#include "data_format.h"
#include "syspara/parameters.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityGuardTest;

namespace OHOS {
    constexpr uint32_t MAX_CONTENT_SIZE = 900;
}

namespace OHOS::Security::SecurityGuardTest {
void RiskCollectTest::SetUpTestCase()
{
}

void RiskCollectTest::TearDownTestCase()
{
}

void RiskCollectTest::SetUp()
{
}

void RiskCollectTest::TearDown()
{
}

class MockUeventListenerImpl : public UeventListenerImpl {
public:
    explicit MockUeventListenerImpl(KernelInterfaceAdapter adapter) : UeventListenerImpl(adapter) {}
    ~MockUeventListenerImpl() override = default;
    MOCK_METHOD0(InitUevent, bool());
    MOCK_METHOD2(UeventListen, int(char *buffer, size_t length));
    MOCK_METHOD2(ParseEvent, void(char *buffer, size_t length));
};

class MockKernelInterfaceAdapter : public KernelInterfaceAdapter {
public:
    MockKernelInterfaceAdapter() = default;
    ~MockKernelInterfaceAdapter() override = default;
    MOCK_METHOD3(Socket, int(int af, int type, int protocol));
    MOCK_METHOD3(Bind, int(int fd, const struct sockaddr* addr, socklen_t addrLength));
    MOCK_METHOD3(Poll, int(struct pollfd* const fds, nfds_t fdCount, int timeout));
    MOCK_METHOD4(Recv, ssize_t(int socket, void* const buf, size_t len, int flags));
    MOCK_METHOD2(Open, int(const char* const pathName, int flags));
    MOCK_METHOD3(Write, ssize_t(int fd, const void* const buf, size_t count));
};

/**
 * @tc.name: TestUeventListener001
 * @tc.desc: Test Start with mock
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(RiskCollectTest, TestUeventListener001, TestSize.Level1)
{
    std::string deviceType = OHOS::system::GetDeviceType();
    if (deviceType == "2in1") {
        KernelInterfaceAdapter adapter;
        MockUeventListenerImpl mockObj(adapter);
        EXPECT_CALL(mockObj, InitUevent).Times(AtLeast(1)).WillRepeatedly(Return(false));
        UeventListener listener(mockObj);
        listener.Start();
    }
}
 
/**
 * @tc.name: TestUeventListener002
 * @tc.desc: Test InitUevent with mock
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(RiskCollectTest, TestUeventListener002, TestSize.Level1)
{
    MockKernelInterfaceAdapter mockObj;
    UeventListenerImpl impl(mockObj);
    EXPECT_CALL(mockObj, Socket).Times(AtLeast(1)).WillOnce(Return(-1)).WillRepeatedly(Return(0));
    EXPECT_CALL(mockObj, Bind).Times(AtLeast(1)).WillOnce(Return(-1)).WillRepeatedly(Return(0));
    bool isSuccess = impl.InitUevent();
    EXPECT_FALSE(isSuccess);
    isSuccess = impl.InitUevent();
    EXPECT_FALSE(isSuccess);
    isSuccess = impl.InitUevent();
    EXPECT_FALSE(isSuccess);
    isSuccess = impl.InitUevent();
    EXPECT_FALSE(isSuccess);
}
 
/**
 * @tc.name: TestUeventListener003
 * @tc.desc: Test UeventListen with mock
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(RiskCollectTest, TestUeventListener003, TestSize.Level1)
{
    MockKernelInterfaceAdapter mockObj;
    UeventListenerImpl impl(mockObj);
    char buffer[1024] = { 0 };
    EXPECT_CALL(mockObj, Poll).Times(AtLeast(1)).WillOnce(Return(0)).WillOnce(
        [] (struct pollfd* const fds, nfds_t fdCount, int timeout) -> int {
            fds->revents = -1;
            return 1;
        }).WillOnce(
            [] (struct pollfd* const fds, nfds_t fdCount, int timeout) -> int {
                fds->revents = 0;
                return 1;
            }).WillRepeatedly(
                [] (struct pollfd* const fds, nfds_t fdCount, int timeout) -> int {
                    fds->revents = 1;
                    return 1;
                });
    EXPECT_CALL(mockObj, Recv).Times(AtLeast(1)).WillOnce(Return(0)).WillRepeatedly(Return(1));
    int32_t count = impl.UeventListen(nullptr, 0);
    EXPECT_EQ(count, 0);
    count = impl.UeventListen(buffer, sizeof(buffer));
    EXPECT_EQ(count, 0);
    count = impl.UeventListen(buffer, sizeof(buffer) - 1);
    EXPECT_EQ(count, 1);
}
 
/**
 * @tc.name: TestUeventListener004
 * @tc.desc: Test ParseEvent with different content
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(RiskCollectTest, TestUeventListener004, TestSize.Level1)
{
    KernelInterfaceAdapter obj;
    UeventListenerImpl impl(obj);
    char buffer[1024] = { 0 };
    impl.ParseEvent(nullptr, 0);
    impl.ParseEvent(buffer, sizeof(buffer) + 1);
    impl.ParseEvent(buffer, sizeof(buffer) - 1);
    EXPECT_CALL(DatabaseManager::GetInstance(), InsertEvent).WillOnce(Return(FAILED)).WillOnce(Return(SUCCESS));
    const char* content = "SG_KERNEL_COLLECT_DATA_CMD=1-0-34-{\"status\":1, \"cred\":1,\"extra\":\"\"}";
    (void) memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
    errno_t rc = memcpy_s(buffer, sizeof(buffer), content, strlen(content));
    EXPECT_TRUE(rc == EOK);
    impl.ParseEvent(buffer, strlen(content));
 
    const char* content1 = "SG_KERNEL_COLLECT_DATA_CMD=1-0-38-{\"status\":\"1\", \"cred\":\"1\",\"extra\":\"\"}";
    (void) memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
    rc = memcpy_s(buffer, sizeof(buffer), content1, strlen(content1));
    EXPECT_TRUE(rc == EOK);
    impl.ParseEvent(buffer, strlen(content1));
 
    const char* content2 = "SG_KERNEL_COLLECT_DATA_CMD=1-0-39-{\"status\":\"1\", \"cred\":\"1\",\"extra\":\"\"}";
    (void) memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
    rc = memcpy_s(buffer, sizeof(buffer), content2, strlen(content2));
    EXPECT_TRUE(rc == EOK);
    impl.ParseEvent(buffer, strlen(content2));
 
    const char* content3 = "SG_KERNEL_COLLECT_DATA_CMD=1-0-34-{\"status\":1, \"cred\":1,\"extra\":\"\"}-0";
    (void) memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
    rc = memcpy_s(buffer, sizeof(buffer), content3, strlen(content3));
    EXPECT_TRUE(rc == EOK);
    impl.ParseEvent(buffer, strlen(content3));
}
 
/**
 * @tc.name: TestUeventNotify001
 * @tc.desc: Test NotifyScan with mock
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(RiskCollectTest, TestUeventNotify001, TestSize.Level1)
{
    MockKernelInterfaceAdapter mockObj;
    UeventNotify notify(mockObj);
    EXPECT_CALL(mockObj, Open).Times(AtLeast(1)).WillOnce(Return(-1)).WillRepeatedly(Return(0));
    EXPECT_CALL(mockObj, Write).Times(AtLeast(1)).WillOnce(Return(0)).WillRepeatedly(Return(1));
    notify.NotifyScan();
    notify.NotifyScan();
    notify.NotifyScan();
}
 
/**
 * @tc.name: TestUeventNotify002
 * @tc.desc: Test AddWhiteList with mock
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(RiskCollectTest, TestUeventNotify002, TestSize.Level1)
{
    std::vector<int64_t> whitelist;
    MockKernelInterfaceAdapter mockObj;
    UeventNotify notify(mockObj);
    EXPECT_CALL(mockObj, Open).Times(AtLeast(1)).WillOnce(Return(-1)).WillRepeatedly(Return(0));
    EXPECT_CALL(mockObj, Write).Times(AtLeast(1)).WillOnce(Return(0)).WillRepeatedly(Return(5));
    notify.AddWhiteList(whitelist);
    whitelist.emplace_back(0);
    notify.AddWhiteList(whitelist);
    notify.AddWhiteList(whitelist);
    notify.AddWhiteList(whitelist);
}
 
/**
 * @tc.name: TestKernelInterfaceAdapter001
 * @tc.desc: Test KernelInterfaceAdapter bind interface
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(RiskCollectTest, TestKernelInterfaceAdapter001, TestSize.Level1)
{
    KernelInterfaceAdapter adapter;
    struct sockaddr_nl addr = {};
    int ret = adapter.Bind(0, reinterpret_cast<const struct sockaddr *>(&addr), sizeof(addr));
    EXPECT_FALSE(ret == 0);
    ret = adapter.Bind(0, nullptr, 0);
    EXPECT_TRUE(ret == -1);
}
 
/**
 * @tc.name: TestKernelInterfaceAdapter002
 * @tc.desc: Test KernelInterfaceAdapter poll interface
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(RiskCollectTest, TestKernelInterfaceAdapter002, TestSize.Level1)
{
    KernelInterfaceAdapter adapter;
    struct pollfd fds = {};
    int ret = adapter.Poll(&fds, 1, -1);
    EXPECT_FALSE(ret == 0);
    ret = adapter.Poll(nullptr, 0, -1);
    EXPECT_TRUE(ret == 0);
}
 
/**
 * @tc.name: TestKernelInterfaceAdapter003
 * @tc.desc: Test KernelInterfaceAdapter recv interface
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(RiskCollectTest, TestKernelInterfaceAdapter003, TestSize.Level1)
{
    KernelInterfaceAdapter adapter;
    char buffer[1] = {};
    int ret = adapter.Recv(0, buffer, sizeof(buffer), 0);
    EXPECT_FALSE(ret == 0);
    ret = adapter.Recv(0, nullptr, 0, 0);
    EXPECT_TRUE(ret == 0);
}
 
/**
 * @tc.name: TestKernelInterfaceAdapter004
 * @tc.desc: Test KernelInterfaceAdapter open interface
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(RiskCollectTest, TestKernelInterfaceAdapter004, TestSize.Level1)
{
    KernelInterfaceAdapter adapter;
    int ret = adapter.Open("/proc/kernel_sg", 0);
    EXPECT_TRUE(ret != 1);
    ret = adapter.Open("test", 0);
    EXPECT_TRUE(ret == -1);
}
 
/**
 * @tc.name: TestKernelInterfaceAdapter005
 * @tc.desc: Test KernelInterfaceAdapter write interface
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(RiskCollectTest, TestKernelInterfaceAdapter005, TestSize.Level1)
{
    KernelInterfaceAdapter adapter;
    char buffer[1] = {};
    int ret = adapter.Write(0, buffer, sizeof(buffer));
    EXPECT_FALSE(ret == 0);
    ret = adapter.Write(0, nullptr, 0);
    EXPECT_TRUE(ret == 0);
}

HWTEST_F(RiskCollectTest, CheckRiskContent001, TestSize.Level1)
{
    std::string content(MAX_CONTENT_SIZE, 'c');
    bool isSuccess = DataFormat::CheckRiskContent(content);
    EXPECT_FALSE(isSuccess);
}

HWTEST_F(RiskCollectTest, ParseConditions001, TestSize.Level1)
{
    std::string conditions;
    RequestCondition reqCondition;
    DataFormat::ParseConditions(conditions, reqCondition);
    EXPECT_TRUE(reqCondition.riskEvent.empty());
}

HWTEST_F(RiskCollectTest, ParseConditions002, TestSize.Level1)
{
    std::string conditions = "{\"eventId\":0}";
    RequestCondition reqCondition;
    DataFormat::ParseConditions(conditions, reqCondition);
    EXPECT_TRUE(reqCondition.riskEvent.empty());
}

HWTEST_F(RiskCollectTest, ParseConditions003, TestSize.Level1)
{
    std::string conditions = "{\"eventId\":[\"t\", \"e\", \"s\", \"t\"]}";
    RequestCondition reqCondition;
    DataFormat::ParseConditions(conditions, reqCondition);
    EXPECT_TRUE(reqCondition.riskEvent.empty());
}

HWTEST_F(RiskCollectTest, ParseConditions004, TestSize.Level1)
{
    std::string conditions = "{\"eventId\":[1, 2, 3, 4]}";
    RequestCondition reqCondition;
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetTableFromEventId).WillOnce(Return("risk_event"))
        .WillRepeatedly(Return("audit_event"));
    DataFormat::ParseConditions(conditions, reqCondition);
    EXPECT_FALSE(reqCondition.riskEvent.empty());
}

HWTEST_F(RiskCollectTest, ParseConditions005, TestSize.Level1)
{
    std::string conditions = "{\"beginTime\":1}";
    RequestCondition reqCondition;
    DataFormat::ParseConditions(conditions, reqCondition);
    EXPECT_TRUE(reqCondition.beginTime.empty());
}

HWTEST_F(RiskCollectTest, ParseConditions006, TestSize.Level1)
{
    std::string conditions = "{\"beginTime\":\"0001\"}";
    RequestCondition reqCondition;
    DataFormat::ParseConditions(conditions, reqCondition);
    EXPECT_TRUE(reqCondition.beginTime == "0001");
}

HWTEST_F(RiskCollectTest, ParseConditions007, TestSize.Level1)
{
    std::string conditions = "{\"endTime\":1}";
    RequestCondition reqCondition;
    DataFormat::ParseConditions(conditions, reqCondition);
    EXPECT_TRUE(reqCondition.endTime.empty());
}

HWTEST_F(RiskCollectTest, ParseConditions008, TestSize.Level1)
{
    std::string conditions = "{\"endTime\":\"0001\"}";
    RequestCondition reqCondition;
    DataFormat::ParseConditions(conditions, reqCondition);
    EXPECT_TRUE(reqCondition.endTime == "0001");
}
}