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

#include "data_collect_kit_test.h"

#include "file_ex.h"
#include "nativetoken_kit.h"
#include "securec.h"
#include "token_setproc.h"

#include "security_guard_define.h"
#include "sg_collect_client.h"

using namespace testing::ext;
using namespace OHOS::Security::SecurityGuardTest;

#ifdef __cplusplus
extern "C" {
#endif
    int32_t ReportSecurityInfo(const struct EventInfoSt *info);
#ifdef __cplusplus
}
#endif

namespace OHOS::Security::SecurityGuardTest {
std::string g_enforceValue = "0";

void DataCollectKitTest::SetUpTestCase()
{
    static const char *permission[] = { "ohos.permission.securityguard.REPORT_SECURITY_INFO" };
    uint64_t tokenId;
    NativeTokenInfoParams infoParams = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = permission,
        .acls = nullptr,
        .processName = "security_guard",
        .aplStr = "system_basic",
    };
    tokenId = GetAccessTokenId(&infoParams);
    SetSelfTokenID(tokenId);
    bool isSuccess = LoadStringFromFile("/sys/fs/selinux/enforce", g_enforceValue);
    if (isSuccess && g_enforceValue == "1") {
        SaveStringToFile("/sys/fs/selinux/enforce", "0");
    }
}

void DataCollectKitTest::TearDownTestCase()
{
    SaveStringToFile("/sys/fs/selinux/enforce", g_enforceValue);
}

void DataCollectKitTest::SetUp()
{
}

void DataCollectKitTest::TearDown()
{
}

/**
 * @tc.name: ReportSecurityInfo001
 * @tc.desc: ReportSecurityInfo with right param
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(DataCollectKitTest, ReportSecurityInfo001, TestSize.Level1)
{
    static int64_t eventId = 1011009000;
    static std::string version = "0";
    static std::string content = "{\"cred\":0,\"extra\":\"\",\"status\":0}";
    EventInfoSt info;
    info.eventId = eventId;
    info.version = version.c_str();
    (void) memset_s(info.content, CONTENT_MAX_LEN, 0, CONTENT_MAX_LEN);
    errno_t rc = memcpy_s(info.content, CONTENT_MAX_LEN, content.c_str(), content.length());
    EXPECT_TRUE(rc == EOK);
    info.contentLen = static_cast<uint32_t>(content.length());
    int ret = ReportSecurityInfo(&info);
    EXPECT_EQ(ret, SecurityGuard::SUCCESS);
}

/**
 * @tc.name: ReportSecurityInfo002
 * @tc.desc: ReportSecurityInfo with wrong cred
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(DataCollectKitTest, ReportSecurityInfo002, TestSize.Level1)
{
    static int64_t eventId = 1011009000;
    static std::string version = "0";
    static std::string content = "{\"cred\":\"0\",\"extra\":\"\",\"status\":0}";
    EventInfoSt info;
    info.eventId = eventId;
    info.version = version.c_str();
    (void) memset_s(info.content, CONTENT_MAX_LEN, 0, CONTENT_MAX_LEN);
    errno_t rc = memcpy_s(info.content, CONTENT_MAX_LEN, content.c_str(), content.length());
    EXPECT_TRUE(rc == EOK);
    info.contentLen = static_cast<uint32_t>(content.length());
    int ret = ReportSecurityInfo(&info);
    EXPECT_EQ(ret, SecurityGuard::SUCCESS);
}

/**
 * @tc.name: ReportSecurityInfo003
 * @tc.desc: ReportSecurityInfo with wrong extra
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(DataCollectKitTest, ReportSecurityInfo003, TestSize.Level1)
{
    static int64_t eventId = 1011009000;
    static std::string version = "0";
    static std::string content = "{\"cred\":0,\"extra\":0,\"status\":0}";
    EventInfoSt info;
    info.eventId = eventId;
    info.version = version.c_str();
    (void) memset_s(info.content, CONTENT_MAX_LEN, 0, CONTENT_MAX_LEN);
    errno_t rc = memcpy_s(info.content, CONTENT_MAX_LEN, content.c_str(), content.length());
    EXPECT_TRUE(rc == EOK);
    info.contentLen = static_cast<uint32_t>(content.length());
    int ret = ReportSecurityInfo(&info);
    EXPECT_EQ(ret, SecurityGuard::SUCCESS);
}

/**
 * @tc.name: ReportSecurityInfo004
 * @tc.desc: ReportSecurityInfo with wrong status
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(DataCollectKitTest, ReportSecurityInfo004, TestSize.Level1)
{
    static int64_t eventId = 1011009000;
    static std::string version = "0";
    static std::string content = "{\"cred\":0,\"extra\":\"\",\"status\":\"0\"}";
    EventInfoSt info;
    info.eventId = eventId;
    info.version = version.c_str();
    (void) memset_s(info.content, CONTENT_MAX_LEN, 0, CONTENT_MAX_LEN);
    errno_t rc = memcpy_s(info.content, CONTENT_MAX_LEN, content.c_str(), content.length());
    EXPECT_TRUE(rc == EOK);
    info.contentLen = static_cast<uint32_t>(content.length());
    int ret = ReportSecurityInfo(&info);
    EXPECT_EQ(ret, SecurityGuard::SUCCESS);
}

/**
 * @tc.name: ReportSecurityInfo005
 * @tc.desc: ReportSecurityInfo with wrong eventId
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(DataCollectKitTest, ReportSecurityInfo005, TestSize.Level1)
{
    static int64_t eventId = 0;
    static std::string version = "0";
    static std::string content = "{\"cred\":0,\"extra\":\"\",\"status\":0}";
    EventInfoSt info;
    info.eventId = eventId;
    info.version = version.c_str();
    (void) memset_s(info.content, CONTENT_MAX_LEN, 0, CONTENT_MAX_LEN);
    errno_t rc = memcpy_s(info.content, CONTENT_MAX_LEN, content.c_str(), content.length());
    EXPECT_TRUE(rc == EOK);
    info.contentLen = static_cast<uint32_t>(content.length());
    int ret = ReportSecurityInfo(&info);
    EXPECT_EQ(ret, SecurityGuard::SUCCESS);
}

/**
 * @tc.name: ReportSecurityInfo006
 * @tc.desc: ReportSecurityInfo with null info
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(DataCollectKitTest, ReportSecurityInfo006, TestSize.Level1)
{
    int ret = ReportSecurityInfo(nullptr);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
}
}