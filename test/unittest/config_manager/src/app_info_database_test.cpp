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

#include "gmock/gmock.h"
#include "rdb_helper.h"
#include "security_guard_define.h"
#define private public
#define protected public
#include "app_info_rdb_helper.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
namespace OHOS {
    std::shared_ptr<NativeRdb::MockRdbHelperInterface> NativeRdb::RdbHelper::instance_ = nullptr;
    std::mutex NativeRdb::RdbHelper::mutex_ {};
}
namespace OHOS::Security::SecurityGuardTest {
namespace {
    constexpr int SUCCESS = 0;
}
class AppInfoDataBaseTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void AppInfoDataBaseTest::SetUpTestCase()
{
}

void AppInfoDataBaseTest::TearDownTestCase()
{
    NativeRdb::RdbHelper::DelInterface();
}

void AppInfoDataBaseTest::SetUp()
{
}

void AppInfoDataBaseTest::TearDown()
{
}

HWTEST_F(AppInfoDataBaseTest, TestAppInfoRdbHelper001, TestSize.Level1)
{
    auto rdbStoreMock = std::make_shared<NativeRdb::RdbStore>();
    auto resultSetMock = std::make_shared<NativeRdb::ResultSet>();
    EXPECT_CALL(*(NativeRdb::RdbHelper::GetInterface()), GetRdbStore)
        .WillRepeatedly([&rdbStoreMock] (
        const NativeRdb::RdbStoreConfig &config, int version, NativeRdb::RdbOpenCallback &openCallback, int &errCode) {
            errCode = SUCCESS;
            return rdbStoreMock;
        });
    EXPECT_CALL(*rdbStoreMock, Query(_, _)).WillOnce(Return(nullptr))
        .WillRepeatedly(
        [&resultSetMock] (const NativeRdb::AbsRdbPredicates &predicates, const std::vector<std::string> columns) {
            return resultSetMock;
        });
    EXPECT_CALL(*resultSetMock, GoToNextRow).WillOnce(Return(SUCCESS)).WillRepeatedly(Return(FAILED));
    EXPECT_CALL(*resultSetMock, GetString).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetInt).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetRowCount).WillOnce(Return(-1)).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetColumnCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetAllColumnNames).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, Close).WillRepeatedly(Return(0));
    AppInfoRdbHelper helper;
    int32_t ret = helper.Init();
    EXPECT_EQ(ret, SUCCESS);
    std::vector<AppInfo> events;
    ret = helper.QueryAllAppInfo(events);
    EXPECT_EQ(ret, DB_OPT_ERR);
    ret = helper.QueryAllAppInfo(events);
    EXPECT_EQ(ret, DB_LOAD_ERR);
    ret = helper.QueryAllAppInfo(events);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(AppInfoDataBaseTest, TestAppInfoRdbHelper002, TestSize.Level1)
{
    auto rdbStoreMock = std::make_shared<NativeRdb::RdbStore>();
    auto resultSetMock = std::make_shared<NativeRdb::ResultSet>();
    EXPECT_CALL(*(NativeRdb::RdbHelper::GetInterface()), GetRdbStore)
        .WillRepeatedly([&rdbStoreMock] (
        const NativeRdb::RdbStoreConfig &config, int version, NativeRdb::RdbOpenCallback &openCallback, int &errCode) {
            errCode = SUCCESS;
            return rdbStoreMock;
        });
    EXPECT_CALL(*rdbStoreMock, Query(_, _))
        .WillRepeatedly(
        [&resultSetMock] (const NativeRdb::AbsRdbPredicates &predicates, const std::vector<std::string> columns) {
            return resultSetMock;
        });
    EXPECT_CALL(*rdbStoreMock, BatchInsert).WillOnce(Return(FAILED)).WillOnce(Return(SUCCESS));
    EXPECT_CALL(*resultSetMock, Close).WillRepeatedly(Return(0));
    EXPECT_CALL(*rdbStoreMock, Insert).WillOnce(Return(FAILED)).WillOnce(Return(SUCCESS));
    AppInfoRdbHelper helper;
    int32_t ret = helper.Init();
    EXPECT_EQ(ret, SUCCESS);
    AppInfo event;
    event.attrs.emplace_back("att");
    event.attrs.emplace_back("att1");
    ret = helper.InsertAppInfo(event);
    EXPECT_EQ(ret, DB_OPT_ERR);
    ret = helper.InsertAppInfo(event);
    EXPECT_EQ(ret, SUCCESS);
    std::vector<AppInfo> events;
    events.emplace_back(event);
    ret = helper.InsertAllAppInfo(events);
    EXPECT_EQ(ret, DB_OPT_ERR);
    ret = helper.InsertAllAppInfo(events);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(AppInfoDataBaseTest, TestAppInfoRdbHelper003, TestSize.Level1)
{
    auto rdbStoreMock = std::make_shared<NativeRdb::RdbStore>();
    auto resultSetMock = std::make_shared<NativeRdb::ResultSet>();
    EXPECT_CALL(*(NativeRdb::RdbHelper::GetInterface()), GetRdbStore)
        .WillRepeatedly([&rdbStoreMock] (
        const NativeRdb::RdbStoreConfig &config, int version, NativeRdb::RdbOpenCallback &openCallback, int &errCode) {
            errCode = SUCCESS;
            return rdbStoreMock;
        });
    EXPECT_CALL(*rdbStoreMock, Query(_, _)).WillOnce(Return(nullptr))
        .WillRepeatedly(
        [&resultSetMock] (const NativeRdb::AbsRdbPredicates &predicates, const std::vector<std::string> columns) {
            return resultSetMock;
        });
    EXPECT_CALL(*rdbStoreMock, Delete).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*rdbStoreMock, Attach).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GoToNextRow).WillOnce(Return(SUCCESS)).WillRepeatedly(Return(FAILED));
    EXPECT_CALL(*resultSetMock, GetString).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetLong).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetInt).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GoToRow).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetRowCount).WillOnce(Return(-1)).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetColumnCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetAllColumnNames).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, Close).WillRepeatedly(Return(0));
    AppInfoRdbHelper helper;
    int32_t ret = helper.Init();
    EXPECT_EQ(ret, SUCCESS);
    std::vector<AppInfo> events;
    std::string appName;
    ret = helper.QueryAppInfosByName(appName, events);
    EXPECT_EQ(ret, DB_OPT_ERR);
    ret = helper.QueryAppInfosByName(appName, events);
    EXPECT_EQ(ret, DB_LOAD_ERR);
    ret = helper.QueryAppInfosByName(appName, events);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(AppInfoDataBaseTest, TestAppInfoRdbHelper004, TestSize.Level1)
{
    auto rdbStoreMock = std::make_shared<NativeRdb::RdbStore>();
    auto resultSetMock = std::make_shared<NativeRdb::ResultSet>();
    EXPECT_CALL(*(NativeRdb::RdbHelper::GetInterface()), GetRdbStore)
        .WillRepeatedly([&rdbStoreMock] (
        const NativeRdb::RdbStoreConfig &config, int version, NativeRdb::RdbOpenCallback &openCallback, int &errCode) {
            errCode = SUCCESS;
            return rdbStoreMock;
        });
    EXPECT_CALL(*rdbStoreMock, Query(_, _)).WillOnce(Return(nullptr))
        .WillRepeatedly(
        [&resultSetMock] (const NativeRdb::AbsRdbPredicates &predicates, const std::vector<std::string> columns) {
            return resultSetMock;
        });
    EXPECT_CALL(*rdbStoreMock, Delete).WillOnce(Return(FAILED)).WillOnce(Return(SUCCESS));
    EXPECT_CALL(*rdbStoreMock, Attach).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GoToNextRow).WillOnce(Return(SUCCESS)).WillRepeatedly(Return(FAILED));
    EXPECT_CALL(*resultSetMock, GetString).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetLong).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetInt).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GoToRow).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetRowCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetColumnCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetAllColumnNames).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, Close).WillRepeatedly(Return(0));
    AppInfoRdbHelper helper;
    int32_t ret = helper.Init();
    EXPECT_EQ(ret, SUCCESS);
    std::vector<AppInfo> events;
    std::string appName;
    ret = helper.DeleteAppInfoByNameAndGlobbalFlag(appName, 0);
    EXPECT_EQ(ret, DB_OPT_ERR);
    ret = helper.DeleteAppInfoByNameAndGlobbalFlag(appName, 0);
    EXPECT_EQ(ret, DB_OPT_ERR);
    ret = helper.DeleteAppInfoByNameAndGlobbalFlag(appName, 0);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(AppInfoDataBaseTest, TestAppInfoRdbHelper005, TestSize.Level1)
{
    auto rdbStoreMock = std::make_shared<NativeRdb::RdbStore>();
    auto resultSetMock = std::make_shared<NativeRdb::ResultSet>();
    EXPECT_CALL(*(NativeRdb::RdbHelper::GetInterface()), GetRdbStore)
        .WillRepeatedly([&rdbStoreMock] (
        const NativeRdb::RdbStoreConfig &config, int version, NativeRdb::RdbOpenCallback &openCallback, int &errCode) {
            errCode = SUCCESS;
            return rdbStoreMock;
        });
    EXPECT_CALL(*rdbStoreMock, Query(_, _)).WillOnce(Return(nullptr))
        .WillRepeatedly(
        [&resultSetMock] (const NativeRdb::AbsRdbPredicates &predicates, const std::vector<std::string> columns) {
            return resultSetMock;
        });
    EXPECT_CALL(*rdbStoreMock, Delete).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*rdbStoreMock, Attach).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GoToNextRow).WillOnce(Return(SUCCESS)).WillRepeatedly(Return(FAILED));;
    EXPECT_CALL(*resultSetMock, GetString).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetLong).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetInt).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GoToRow).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetRowCount).WillOnce(Return(-1)).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetColumnCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, Close).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetAllColumnNames).WillRepeatedly(
        [] (std::vector<std::string> &columnNames) {
            columnNames.emplace_back(ID);
            columnNames.emplace_back(APP_NAME);
            columnNames.emplace_back(APP_FINGERPRINT);
            columnNames.emplace_back(APP_ATTRIBUTES);
            columnNames.emplace_back(IS_GLOBAL_APP);
            return SUCCESS;
        });
    std::vector<AppInfo> events;
    std::string attr;
    AppInfoRdbHelper helper;
    helper.GetInstance();
    int32_t ret = helper.Init();
    EXPECT_EQ(ret, SUCCESS);
    ret = helper.QueryAppInfoByAttribute(attr, events);
    EXPECT_EQ(ret, DB_OPT_ERR);
    ret = helper.QueryAppInfoByAttribute(attr, events);
    EXPECT_EQ(ret, DB_LOAD_ERR);
    ret = helper.QueryAppInfoByAttribute(attr, events);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(AppInfoDataBaseTest, TestAppInfoRdbHelper006, TestSize.Level1)
{
    auto rdbStoreMock = std::make_shared<NativeRdb::RdbStore>();
    auto resultSetMock = std::make_shared<NativeRdb::ResultSet>();
    EXPECT_CALL(*(NativeRdb::RdbHelper::GetInterface()), GetRdbStore)
        .WillRepeatedly([&rdbStoreMock] (
        const NativeRdb::RdbStoreConfig &config, int version, NativeRdb::RdbOpenCallback &openCallback, int &errCode) {
            errCode = SUCCESS;
            return rdbStoreMock;
        });
    EXPECT_CALL(*rdbStoreMock, Query(_, _)).WillOnce(Return(nullptr))
        .WillRepeatedly(
        [&resultSetMock] (const NativeRdb::AbsRdbPredicates &predicates, const std::vector<std::string> columns) {
            return resultSetMock;
        });
    EXPECT_CALL(*rdbStoreMock, Delete).WillOnce(Return(FAILED)).WillOnce(Return(SUCCESS));
    EXPECT_CALL(*rdbStoreMock, Attach).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GoToNextRow).WillOnce(Return(SUCCESS)).WillRepeatedly(Return(FAILED));
    EXPECT_CALL(*resultSetMock, GetString).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetLong).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetInt).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GoToRow).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetRowCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetColumnCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetAllColumnNames).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, Close).WillRepeatedly(Return(0));
    AppInfoRdbHelper helper;
    int32_t ret = helper.Init();
    EXPECT_EQ(ret, SUCCESS);
    std::vector<AppInfo> events;
    int global = 0;
    ret = helper.DeleteAppInfoByIsGlobalApp(global);
    EXPECT_EQ(ret, DB_OPT_ERR);
    ret = helper.DeleteAppInfoByIsGlobalApp(global);
    EXPECT_EQ(ret, DB_OPT_ERR);
    ret = helper.DeleteAppInfoByIsGlobalApp(global);
    EXPECT_EQ(ret, SUCCESS);
}
}
