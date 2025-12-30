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

#include "security_collector_run_manager_test.h"

#include <thread>

#include "directory_ex.h"
#include "file_ex.h"
#include "gmock/gmock.h"
#include "system_ability_definition.h"

#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#define private public
#define protected public
#include "data_collection.h"
#include "security_collector_run_manager.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityCollector;

namespace OHOS {
}

namespace OHOS::Security::SecurityCollector {
void SecurityCollectorRunManagerTest::SetUpTestCase()
{
}

void SecurityCollectorRunManagerTest::TearDownTestCase()
{
}

void SecurityCollectorRunManagerTest::SetUp()
{
}

void SecurityCollectorRunManagerTest::TearDown()
{
}

HWTEST_F(SecurityCollectorRunManagerTest, StartCollector001, TestSize.Level1)
{
    Event event {};
    event.eventId = 111;
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event);
    auto subscribe = std::make_shared<SecurityCollector::SecurityCollectorSubscriber>("security_guard", subscribeInfo,
        nullptr, nullptr);
    SecurityCollector::SecurityCollectorRunManager::GetInstance().collectorRunManager_[event.eventId] = subscribe;
    EXPECT_FALSE(SecurityCollector::SecurityCollectorRunManager::GetInstance().StartCollector(subscribe));
}

HWTEST_F(SecurityCollectorRunManagerTest, StartCollector002, TestSize.Level1)
{
    Event event {};
    event.eventId = 111;
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event);
    auto subscribe = std::make_shared<SecurityCollector::SecurityCollectorSubscriber>("security_guard", subscribeInfo,
        nullptr, nullptr);
    SecurityCollector::SecurityCollectorRunManager::GetInstance().collectorRunManager_.clear();
    SecurityCollectorRunManager::CollectorListenner listenner(subscribe);
    listenner.OnNotify(event);
    SecurityCollectorRunManager::GetInstance().NotifySubscriber(event);
    EXPECT_CALL(DataCollection::GetInstance(), StartCollectors).WillOnce(Return(true));
    EXPECT_TRUE(SecurityCollector::SecurityCollectorRunManager::GetInstance().StartCollector(subscribe));
}

HWTEST_F(SecurityCollectorRunManagerTest, StartCollector003, TestSize.Level1)
{
    Event event {};
    event.eventId = 111;
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event);
    auto subscribe = std::make_shared<SecurityCollector::SecurityCollectorSubscriber>("security_guard", subscribeInfo,
        nullptr, nullptr);
    SecurityCollector::SecurityCollectorRunManager::GetInstance().collectorRunManager_.clear();
    EXPECT_CALL(DataCollection::GetInstance(), StartCollectors).WillOnce(Return(false));
    EXPECT_FALSE(SecurityCollector::SecurityCollectorRunManager::GetInstance().StartCollector(subscribe));
}

HWTEST_F(SecurityCollectorRunManagerTest, StartCollector004, TestSize.Level1)
{
    EXPECT_FALSE(SecurityCollector::SecurityCollectorRunManager::GetInstance().StartCollector(nullptr));
}

HWTEST_F(SecurityCollectorRunManagerTest, StopCollector001, TestSize.Level1)
{
    Event event {};
    event.eventId = 111;
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event);
    auto subscribe = std::make_shared<SecurityCollector::SecurityCollectorSubscriber>("security_guard", subscribeInfo,
        nullptr, nullptr);
    EXPECT_FALSE(SecurityCollector::SecurityCollectorRunManager::GetInstance().StopCollector(subscribe));
}

HWTEST_F(SecurityCollectorRunManagerTest, StopCollector002, TestSize.Level1)
{
    Event event {};
    event.eventId = 111;
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event);
    auto subscribe = std::make_shared<SecurityCollector::SecurityCollectorSubscriber>("security_guard", subscribeInfo,
        nullptr, nullptr);
    SecurityCollector::SecurityCollectorRunManager::GetInstance().collectorRunManager_[event.eventId] = subscribe;
    EXPECT_CALL(DataCollection::GetInstance(), StopCollectors).WillOnce(Return(false));
    EXPECT_FALSE(SecurityCollector::SecurityCollectorRunManager::GetInstance().StopCollector(subscribe));
}

HWTEST_F(SecurityCollectorRunManagerTest, StopCollector003, TestSize.Level1)
{
    Event event {};
    event.eventId = 111;
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event);
    auto subscribe = std::make_shared<SecurityCollector::SecurityCollectorSubscriber>("security_guard", subscribeInfo,
        nullptr, nullptr);
    auto errSubscribe = std::make_shared<SecurityCollector::SecurityCollectorSubscriber>("security", subscribeInfo,
        nullptr, nullptr);
    SecurityCollector::SecurityCollectorRunManager::GetInstance().collectorRunManager_[event.eventId] = subscribe;
    EXPECT_FALSE(SecurityCollector::SecurityCollectorRunManager::GetInstance().StopCollector(errSubscribe));
}

HWTEST_F(SecurityCollectorRunManagerTest, StopCollector004, TestSize.Level1)
{
    EXPECT_FALSE(SecurityCollector::SecurityCollectorRunManager::GetInstance().StopCollector(nullptr));
}

HWTEST_F(SecurityCollectorRunManagerTest, StopCollector005, TestSize.Level1)
{
    Event event {};
    event.eventId = 111;
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event);
    auto subscribe = std::make_shared<SecurityCollector::SecurityCollectorSubscriber>("security_guard", subscribeInfo,
        nullptr, nullptr);
    SecurityCollector::SecurityCollectorRunManager::GetInstance().collectorRunManager_[event.eventId] = subscribe;
    EXPECT_CALL(DataCollection::GetInstance(), StopCollectors).WillOnce(Return(true));
    EXPECT_TRUE(SecurityCollector::SecurityCollectorRunManager::GetInstance().StopCollector(subscribe));
}
}