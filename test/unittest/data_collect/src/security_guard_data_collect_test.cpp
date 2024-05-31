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

#include "security_guard_data_collect_test.h"

#include "directory_ex.h"
#include "file_ex.h"
#include "gmock/gmock.h"

#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "store_define.h"
#include "rdb_helper.h"
#define private public
#define protected public
#include "config_data_manager.h"
#include "database.h"
#include "database_manager.h"
#include "device_manager.h"
#include "os_account_manager.h"
#include "preferences_helper.h"
#include "risk_event_rdb_helper.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityGuardTest;

namespace OHOS {
    std::shared_ptr<NativeRdb::MockRdbHelperInterface> NativeRdb::RdbHelper::instance_ = nullptr;
    std::shared_ptr<AccountSA::MockOsAccountManagerInterface> AccountSA::OsAccountManager::instance_ = nullptr;
    std::shared_ptr<NativePreferences::MockPreferenceHelperInterface>
        NativePreferences::PreferencesHelper::instance_ = nullptr;
    std::mutex NativeRdb::RdbHelper::mutex_ {};
    std::mutex AccountSA::OsAccountManager::mutex_ {};
    std::mutex NativePreferences::PreferencesHelper::mutex_ {};
}

namespace OHOS::Security::SecurityGuardTest {
namespace {
    constexpr int SUCCESS = 0;
    constexpr int FAILED = -1;
}

void SecurityGuardDataCollectTest::SetUpTestCase()
{
}

void SecurityGuardDataCollectTest::TearDownTestCase()
{
    NativeRdb::RdbHelper::DelInterface();
}

void SecurityGuardDataCollectTest::SetUp()
{
}

void SecurityGuardDataCollectTest::TearDown()
{
}

HWTEST_F(SecurityGuardDataCollectTest, TestRiskEventRdbHelperMock001, TestSize.Level1)
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
    EXPECT_CALL(*rdbStoreMock, Delete).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*rdbStoreMock, Attach).WillRepeatedly(Return(0));
    EXPECT_CALL(*rdbStoreMock, BatchInsert).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*resultSetMock, GoToNextRow).WillRepeatedly(Return(-1));
    EXPECT_CALL(*resultSetMock, GetString).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetLong).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetInt).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GoToRow).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetRowCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetColumnCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetAllColumnNames).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, Close).WillRepeatedly(Return(0));
    EXPECT_CALL(*rdbStoreMock, Insert).WillOnce(Return(FAILED)).WillOnce(Return(SUCCESS));
    RiskEventRdbHelper helper;
    int32_t ret = helper.Init();
    EXPECT_EQ(ret, SUCCESS);
    SecEvent event;
    ret = helper.InsertEvent(event);
    EXPECT_EQ(ret, DB_OPT_ERR);
    ret = helper.InsertEvent(event);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestRiskEventRdbHelperMock002, TestSize.Level1)
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
    EXPECT_CALL(*rdbStoreMock, BatchInsert).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*resultSetMock, GoToNextRow).WillOnce(Return(SUCCESS)).WillRepeatedly(Return(FAILED));
    EXPECT_CALL(*resultSetMock, GetString).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetLong).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetInt).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GoToRow).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetRowCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetColumnCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetAllColumnNames).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, Close).WillRepeatedly(Return(0));
    EXPECT_CALL(*rdbStoreMock, Insert).WillRepeatedly(Return(SUCCESS));
    RiskEventRdbHelper helper;
    int32_t ret = helper.Init();
    EXPECT_EQ(ret, SUCCESS);
    int64_t eventId = 0;
    SecEvent event;
    ret = helper.QueryRecentEventByEventId(eventId, event);
    EXPECT_EQ(ret, DB_OPT_ERR);
    ret = helper.QueryRecentEventByEventId(eventId, event);
    EXPECT_EQ(ret, SUCCESS);
    ret = helper.QueryRecentEventByEventId(eventId, event);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestRiskEventRdbHelperMock003, TestSize.Level1)
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
    EXPECT_CALL(*rdbStoreMock, Attach).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*rdbStoreMock, BatchInsert).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*resultSetMock, GoToNextRow).WillOnce(Return(SUCCESS)).WillRepeatedly(Return(FAILED));
    EXPECT_CALL(*resultSetMock, GetString).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetLong).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetInt).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GoToRow).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetRowCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetColumnCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetAllColumnNames).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, Close).WillRepeatedly(Return(0));
    EXPECT_CALL(*rdbStoreMock, Insert).WillRepeatedly(Return(SUCCESS));
    RiskEventRdbHelper helper;
    int32_t ret = helper.Init();
    EXPECT_EQ(ret, SUCCESS);
    std::vector<int64_t> eventIds;
    std::vector<SecEvent> events;
    ret = helper.QueryRecentEventByEventId(eventIds, events);
    EXPECT_EQ(ret, BAD_PARAM);
    eventIds.emplace_back(0);
    ret = helper.QueryRecentEventByEventId(eventIds, events);
    EXPECT_EQ(ret, DB_OPT_ERR);
    ret = helper.QueryRecentEventByEventId(eventIds, events);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestRiskEventRdbHelperMock004, TestSize.Level1)
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
    EXPECT_CALL(*rdbStoreMock, Delete).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*rdbStoreMock, Attach).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*rdbStoreMock, BatchInsert).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*resultSetMock, GoToNextRow).WillOnce(Return(SUCCESS)).WillRepeatedly(Return(FAILED));
    EXPECT_CALL(*resultSetMock, GetString).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetLong).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetInt).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GoToRow).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetRowCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetColumnCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetAllColumnNames).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, Close).WillRepeatedly(Return(0));
    EXPECT_CALL(*rdbStoreMock, Insert).WillRepeatedly(Return(SUCCESS));
    RiskEventRdbHelper helper;
    int32_t ret = helper.Init();
    EXPECT_EQ(ret, SUCCESS);
    std::vector<int64_t> eventIds;
    std::vector<SecEvent> events;
    ret = helper.QueryEventByEventId(eventIds, events);
    EXPECT_EQ(ret, BAD_PARAM);
    eventIds.emplace_back(0);
    ret = helper.QueryEventByEventId(eventIds, events);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestRiskEventRdbHelperMock005, TestSize.Level1)
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
    EXPECT_CALL(*rdbStoreMock, Delete).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*rdbStoreMock, Attach).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*rdbStoreMock, BatchInsert).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*resultSetMock, GoToNextRow).WillOnce(Return(SUCCESS)).WillRepeatedly(Return(FAILED));
    EXPECT_CALL(*resultSetMock, GetString).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetLong).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetInt).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GoToRow).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetRowCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetColumnCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetAllColumnNames).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, Close).WillRepeatedly(Return(0));
    EXPECT_CALL(*rdbStoreMock, Insert).WillRepeatedly(Return(SUCCESS));
    RiskEventRdbHelper helper;
    int32_t ret = helper.Init();
    EXPECT_EQ(ret, SUCCESS);
    std::vector<int64_t> eventIds;
    std::vector<SecEvent> events;
    std::string data = "202301011200";
    ret = helper.QueryEventByEventIdAndDate(eventIds, events, data, data);
    EXPECT_EQ(ret, BAD_PARAM);
    eventIds.emplace_back(0);
    ret = helper.QueryEventByEventIdAndDate(eventIds, events, data, data);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestRiskEventRdbHelperMock006, TestSize.Level1)
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
    EXPECT_CALL(*rdbStoreMock, Delete).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*rdbStoreMock, Attach).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*rdbStoreMock, BatchInsert).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*resultSetMock, GoToNextRow).WillOnce(Return(SUCCESS)).WillRepeatedly(Return(FAILED));
    EXPECT_CALL(*resultSetMock, GetString).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetLong).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetInt).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GoToRow).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetRowCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetColumnCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetAllColumnNames).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, Close).WillRepeatedly(Return(0));
    EXPECT_CALL(*rdbStoreMock, Insert).WillRepeatedly(Return(SUCCESS));
    RiskEventRdbHelper helper;
    int32_t ret = helper.Init();
    EXPECT_EQ(ret, SUCCESS);
    std::vector<int64_t> eventIds;
    std::vector<SecEvent> events;
    std::string data = "202301011200";
    ret = helper.QueryEventByEventIdAndDate(eventIds, events, data, data);
    EXPECT_EQ(ret, BAD_PARAM);
    eventIds.emplace_back(0);
    ret = helper.QueryEventByEventIdAndDate(eventIds, events, data, data);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestRiskEventRdbHelperMock007, TestSize.Level1)
{
    auto rdbStoreMock = std::make_shared<NativeRdb::RdbStore>();
    EXPECT_CALL(*(NativeRdb::RdbHelper::GetInterface()), GetRdbStore)
        .WillRepeatedly([&rdbStoreMock] (
        const NativeRdb::RdbStoreConfig &config, int version, NativeRdb::RdbOpenCallback &openCallback, int &errCode) {
            errCode = SUCCESS;
            return rdbStoreMock;
        });
    EXPECT_CALL(*rdbStoreMock, Count).WillOnce(Return(FAILED)).WillRepeatedly(Return(SUCCESS));
    RiskEventRdbHelper helper;
    int32_t ret = helper.Init();
    EXPECT_EQ(ret, SUCCESS);
    int64_t count = helper.CountAllEvent();
    EXPECT_EQ(count, 0);
    count = helper.CountAllEvent();
    EXPECT_EQ(count, 0);
}

HWTEST_F(SecurityGuardDataCollectTest, TestRiskEventRdbHelperMock008, TestSize.Level1)
{
    auto rdbStoreMock = std::make_shared<NativeRdb::RdbStore>();
    EXPECT_CALL(*(NativeRdb::RdbHelper::GetInterface()), GetRdbStore)
        .WillRepeatedly([&rdbStoreMock] (
        const NativeRdb::RdbStoreConfig &config, int version, NativeRdb::RdbOpenCallback &openCallback, int &errCode) {
            errCode = SUCCESS;
            return rdbStoreMock;
        });
    EXPECT_CALL(*rdbStoreMock, Count).WillOnce(Return(FAILED)).WillRepeatedly(Return(SUCCESS));
    RiskEventRdbHelper helper;
    int32_t ret = helper.Init();
    EXPECT_EQ(ret, SUCCESS);
    int64_t count = helper.CountEventByEventId(0);
    EXPECT_EQ(count, 0);
    count = helper.CountEventByEventId(0);
    EXPECT_EQ(count, 0);
}

HWTEST_F(SecurityGuardDataCollectTest, TestRiskEventRdbHelperMock009, TestSize.Level1)
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
    EXPECT_CALL(*rdbStoreMock, Delete).WillOnce(Return(FAILED)).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*rdbStoreMock, Attach).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*rdbStoreMock, BatchInsert).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*resultSetMock, GoToNextRow).WillOnce(Return(SUCCESS)).WillRepeatedly(Return(FAILED));
    EXPECT_CALL(*resultSetMock, GetString).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetLong).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetInt).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GoToRow).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetRowCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetColumnCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetAllColumnNames).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, Close).WillRepeatedly(Return(0));
    EXPECT_CALL(*rdbStoreMock, Insert).WillRepeatedly(Return(SUCCESS));
    RiskEventRdbHelper helper;
    int32_t ret = helper.Init();
    EXPECT_EQ(ret, SUCCESS);
    int64_t eventId = 0;
    int64_t count = 0;
    ret = helper.DeleteOldEventByEventId(eventId, count);
    EXPECT_EQ(ret, DB_OPT_ERR);
    ret = helper.DeleteOldEventByEventId(eventId, count);
    EXPECT_EQ(ret, DB_OPT_ERR);
    ret = helper.DeleteOldEventByEventId(eventId, count);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestRiskEventRdbHelperMock010, TestSize.Level1)
{
    auto rdbStoreMock = std::make_shared<NativeRdb::RdbStore>();
    EXPECT_CALL(*(NativeRdb::RdbHelper::GetInterface()), GetRdbStore)
        .WillRepeatedly([&rdbStoreMock] (
        const NativeRdb::RdbStoreConfig &config, int version, NativeRdb::RdbOpenCallback &openCallback, int &errCode) {
            errCode = SUCCESS;
            return rdbStoreMock;
        });
    EXPECT_CALL(*rdbStoreMock, Delete).WillOnce(Return(FAILED)).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*rdbStoreMock, Attach).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*rdbStoreMock, BatchInsert).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*rdbStoreMock, Insert).WillRepeatedly(Return(SUCCESS));
    RiskEventRdbHelper helper;
    int32_t ret = helper.Init();
    EXPECT_EQ(ret, SUCCESS);
    int64_t eventId = 0;
    ret = helper.DeleteAllEventByEventId(eventId);
    EXPECT_EQ(ret, DB_OPT_ERR);
    ret = helper.DeleteAllEventByEventId(eventId);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestRiskEventRdbHelperMock011, TestSize.Level1)
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
    EXPECT_CALL(*rdbStoreMock, Attach).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*rdbStoreMock, BatchInsert).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*resultSetMock, GoToNextRow).WillOnce(Return(SUCCESS)).WillRepeatedly(Return(FAILED));
    EXPECT_CALL(*resultSetMock, GetString).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetLong).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetInt).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GoToRow).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetRowCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetColumnCount).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, GetAllColumnNames).WillRepeatedly(Return(0));
    EXPECT_CALL(*resultSetMock, Close).WillRepeatedly(Return(0));
    EXPECT_CALL(*rdbStoreMock, Insert).WillRepeatedly(Return(SUCCESS));
    RiskEventRdbHelper helper;
    int32_t ret = helper.Init();
    EXPECT_EQ(ret, SUCCESS);
    NativeRdb::RdbPredicates predicates("");
    std::vector<SecEvent> events;
    ret = helper.QueryEventBase(predicates, events);
    EXPECT_EQ(ret, DB_OPT_ERR);
    ret = helper.QueryEventBase(predicates, events);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectTest, TestRiskEventRdbHelperMock012, TestSize.Level1)
{
    auto resultSetMock = std::make_shared<NativeRdb::ResultSet>();
    EXPECT_CALL(*resultSetMock, GetRowCount).WillOnce(Return(FAILED)).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*resultSetMock, GetColumnCount).WillOnce(Return(FAILED)).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*resultSetMock, GetAllColumnNames).WillOnce(Return(FAILED)).WillRepeatedly(
        [] (std::vector<std::string> &columnNames) {
            columnNames.emplace_back(ID);
            columnNames.emplace_back(EVENT_ID);
            columnNames.emplace_back(VERSION);
            columnNames.emplace_back(DATE);
            columnNames.emplace_back(CONTENT);
            columnNames.emplace_back(USER_ID);
            columnNames.emplace_back(DEVICE_ID);
            return SUCCESS;
        });
    RiskEventRdbHelper helper;
    SecEventTableInfo table;
    int32_t ret = helper.GetResultSetTableInfo(resultSetMock, table);
    EXPECT_EQ(ret, DB_LOAD_ERR);
    ret = helper.GetResultSetTableInfo(resultSetMock, table);
    EXPECT_EQ(ret, DB_LOAD_ERR);
    ret = helper.GetResultSetTableInfo(resultSetMock, table);
    EXPECT_EQ(ret, DB_LOAD_ERR);
    ret = helper.GetResultSetTableInfo(resultSetMock, table);
    EXPECT_EQ(ret, SUCCESS);
}
}