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
#include "securityguard_napi_test.h"
#include "gmock/gmock.h"
#include "file_ex.h"
#define private public
#define protected public
#include "security_guard_sdk_adaptor.h"
#include "napi_request_data_manager.h"
#include "napi_security_event_querier.h"
#undef private
#undef protected
#include "event_info.h"
using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityGuardTest;

namespace OHOS::Security::SecurityGuardTest {
bool SecurityGuardNapiTest::isEnforcing_ = false;
void SecurityGuardNapiTest::SetUpTestCase()
{
    string isEnforcing;
    LoadStringFromFile("/sys/fs/selinux/enforce", isEnforcing);
    if (isEnforcing.compare("1") == 0) {
        SecurityGuardNapiTest::isEnforcing_ = true;
        SaveStringToFile("/sys/fs/selinux/enforce", "0");
    }
}
void SecurityGuardNapiTest::TearDownTestCase()
{
    if (SecurityGuardNapiTest::isEnforcing_) {
        SaveStringToFile("/sys/fs/selinux/enforce", "1");
    }
}
void SecurityGuardNapiTest::SetUp()
{
}
void SecurityGuardNapiTest::TearDown()
{
}

HWTEST_F(SecurityGuardNapiTest, RequestSecurityEventInfo01, TestSize.Level1)
{
    RequestRiskDataCallback callback {};
    std::string str = "test";
    EXPECT_EQ(SecurityGuardSdkAdaptor::RequestSecurityEventInfo(str, str, callback),
        SecurityGuard::NO_PERMISSION);
}

HWTEST_F(SecurityGuardNapiTest, InnerRequestSecurityModelResult01, TestSize.Level1)
{
    OHOS::Security::SecurityGuard::SecurityGuardRiskCallback callback {};
    EXPECT_EQ(SecurityGuardSdkAdaptor::InnerRequestSecurityModelResult("test", 0, "test", callback),
        SecurityGuard::NO_PERMISSION);
}

HWTEST_F(SecurityGuardNapiTest, InnerReportSecurityInfo01, TestSize.Level1)
{
    std::shared_ptr<EventInfo> info {};
    EXPECT_EQ(SecurityGuardSdkAdaptor::InnerReportSecurityInfo(info), SecurityGuard::BAD_PARAM);
}

HWTEST_F(SecurityGuardNapiTest, StartCollector01, TestSize.Level1)
{
    SecurityCollector::Event event {};
    EXPECT_EQ(SecurityGuardSdkAdaptor::StartCollector(event, 0), SecurityGuard::NO_PERMISSION);
}

HWTEST_F(SecurityGuardNapiTest, StopCollector01, TestSize.Level1)
{
    SecurityCollector::Event event {};
    EXPECT_EQ(SecurityGuardSdkAdaptor::StopCollector(event), SecurityGuard::NO_PERMISSION);
}

HWTEST_F(SecurityGuardNapiTest, QuerySecurityEvent01, TestSize.Level1)
{
    std::vector<SecurityCollector::SecurityEventRuler> rulers {};
    std::shared_ptr<SecurityEventQueryCallback> callback {};
    EXPECT_EQ(SecurityGuardSdkAdaptor::QuerySecurityEvent(rulers, callback), SecurityGuard::NULL_OBJECT);
}

HWTEST_F(SecurityGuardNapiTest, Subscribe01, TestSize.Level1)
{
    std::shared_ptr<SecurityCollector::ICollectorSubscriber> subscriber {};
    NapiRequestDataManager manager {};
    napi_env env {};
    manager.DeleteContext(env);
    manager.AddDataCallback(env);
    manager.DelDataCallback(env);
    manager.GetDataCallback(env);
    EXPECT_EQ(SecurityGuardSdkAdaptor::Subscribe(subscriber), SecurityGuard::NULL_OBJECT);
}

HWTEST_F(SecurityGuardNapiTest, UnSubscribe01, TestSize.Level1)
{
    std::shared_ptr<SecurityCollector::ICollectorSubscriber> subscriber {};
    auto context = new (std::nothrow) QuerySecurityEventContext;
    CALLBACK_FUNC callback {};
    RELEASE_FUNC release {};
    ON_COMPLETE_FUNC handler {};
    NapiSecurityEventQuerier querier(context, handler);
    querier.RunCallback(context, callback, release);
    std::vector<SecurityCollector::SecurityEvent> events {};
    querier.OnQuery(events);
    querier.OnComplete();
    querier.OnError("test");
    EXPECT_EQ(SecurityGuardSdkAdaptor::Unsubscribe(subscriber), SecurityGuard::NULL_OBJECT);
}

HWTEST_F(SecurityGuardNapiTest, ConfigUpdate01, TestSize.Level1)
{
    SecurityGuard::SecurityConfigUpdateInfo updateInfo {};
    EXPECT_EQ(SecurityGuardSdkAdaptor::ConfigUpdate(updateInfo), SecurityGuard::NO_PERMISSION);
}
}