/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef SECURITY_GUARD_OBTAINDATA_KIT_TEST_H
#define SECURITY_GUARD_OBTAINDATA_KIT_TEST_H

#include <gtest/gtest.h>

#include "sg_obtaindata_client.h"
#include "security_guard_define.h"

namespace OHOS::Security::SecurityGuardTest {
class ObtainDataKitTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;

    class RequestSecurityEventInfoCallbackMock : public SecurityGuard::RequestSecurityEventInfoCallback {
    public:
        RequestSecurityEventInfoCallbackMock() = default;
        ~RequestSecurityEventInfoCallbackMock() override = default;
        int32_t OnSecurityEventInfoResult(std::string &devId, std::string &riskData, uint32_t status) override
        {
            return SecurityGuard::ErrorCode::SUCCESS;
        }
    };

    std::shared_ptr<SecurityGuard::RequestSecurityEventInfoCallback> callback_;
};
} // namespace OHOS::Security::SecurityGuardTest

#endif  // SECURITY_GUARD_OBTAINDATA_KIT_TEST_H
