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

#ifndef SECURITY_GUARD_COLLECTOR_INTERFACE_TEST
#define SECURITY_GUARD_COLLECTOR_INTERFACE_TEST

#include <gtest/gtest.h>
#include "i_collector_subscriber.h"
#include "i_collector_fwk.h"
#include "security_collector_subscriber.h"

namespace OHOS::Security::SecurityGuardTest {
class CollectorInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};
}  // namespace OHOS::Security::SecurityGuardTest

namespace OHOS::Security::SecurityCollector {
class CollectorSubscriberTestImpl : public ICollectorSubscriber {
public:
    CollectorSubscriberTestImpl(const Event &event, int64_t duration, bool isNotify)
        : ICollectorSubscriber(event, duration, isNotify) {}
    virtual ~CollectorSubscriberTestImpl() override = default;
    virtual int32_t OnNotify(const Event &event) override;
private:
    SecurityCollectorSubscribeInfo subscribeInfo_;
};

class CollectorFwkTestImpl : public ICollectorFwk {
public:
    CollectorFwkTestImpl(const std::shared_ptr<SecurityCollectorSubscriber> &subscriber) : subscriber_(subscriber) {}
    void OnNotify(const Event &event) override;
private:
    std::shared_ptr<SecurityCollectorSubscriber> subscriber_;
};
}

#endif  // SECURITY_GUARD_COLLECTOR_INTERFACE_TEST