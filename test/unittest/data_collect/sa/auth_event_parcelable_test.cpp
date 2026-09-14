/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include "parcel.h"
#include "auth_event.h"

using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;

namespace {
class AuthEventParcelableTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(AuthEventParcelableTest, AuthEventMarshalling001, TestSize.Level0)
{
    AuthEvent event(1001L, "{\"action\":\"block\"}", "{\"scene\":\"kernel\"}");
    OHOS::Parcel parcel {};
    ASSERT_TRUE(event.Marshalling(parcel));
    AuthEvent *result = AuthEvent::Unmarshalling(parcel);
    ASSERT_NE(nullptr, result);
    EXPECT_EQ(1001L, result->GetEventId());
    EXPECT_STREQ("{\"action\":\"block\"}", result->GetContent().c_str());
    EXPECT_STREQ("{\"scene\":\"kernel\"}", result->GetMetadata().c_str());
    delete result;
}

HWTEST_F(AuthEventParcelableTest, AuthEventMarshalling002, TestSize.Level0)
{
    AuthEvent event;
    OHOS::Parcel parcel {};
    ASSERT_TRUE(event.Marshalling(parcel));
    AuthEvent *result = AuthEvent::Unmarshalling(parcel);
    ASSERT_NE(nullptr, result);
    EXPECT_EQ(0L, result->GetEventId());
    EXPECT_TRUE(result->GetContent().empty());
    EXPECT_TRUE(result->GetMetadata().empty());
    delete result;
}

HWTEST_F(AuthEventParcelableTest, AuthEventUnmarshallingInvalid, TestSize.Level0)
{
    OHOS::Parcel parcel {};
    EXPECT_EQ(nullptr, AuthEvent::Unmarshalling(parcel));
}
}
