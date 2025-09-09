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
#include "security_guard_define.h"
#include "store_define.h"
#include <memory>
#include <filesystem>

#define private public
#define protected public
#include "risk_event_rdb_helper.h"
#include "sg_sqlite_helper.h"
#include "sqlite_helper.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
namespace fs = std::filesystem;
namespace OHOS::Security::SecurityGuardTest {
namespace {
    const std::string& g_testDbName = "ext_test.db";
    const std::string& g_testDbDir = "/data/test_ext/";
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
}

void AppInfoDataBaseTest::SetUp()
{
}

void AppInfoDataBaseTest::TearDown()
{
}

class StatementTest : public testing::Test {
protected:
    static void SetUpTestSuite()
    {
        sqlite3_open(":memory:", &db);
        const char* createTable =
            "CREATE TABLE test ("
            "id INTEGER PRIMARY KEY,"
            "name TEXT,"
            "value INTEGER,"
            "timestamp BIGINT;)";
        sqlite3_exec(db, createTable, nullptr, nullptr, nullptr);
    }

    static void TearDownTestSuite()
    {
        sqlite3_close(db);
    }

    void SetUp() override
    {
        const char* insertData =
            "INSERT INFO test (name, value, timestamp) VALUES "
            "('test1', 100, 1630000000000),"
            "('test2', 200, 1630000000001);";
        sqlite3_exec(db, insertData, nullptr, nullptr, nullptr);
    }

    void TearDown() override
    {
        sqlite3_exec(db, "DELETE FROM test", nullptr, nullptr, nullptr);
    }

    static sqlite3* db;
};

sqlite3* StatementTest::db = nullptr;

HWTEST_F(AppInfoDataBaseTest, DatabaseTest, TestSize.Level1)
{
    int32_t int32 = 0;
    int64_t int64 = 0;
    Database database{};
    std::string string;
    GenericValues value{};
    std::vector<GenericValues> values;
    std::vector<std::string> strings;
    EXPECT_EQ(database.Insert(int64, string, value), FAILED);
    EXPECT_EQ(database.BatchInsert(int64, string, values), FAILED);
    EXPECT_EQ(database.Update(int32, string, value), FAILED);
    EXPECT_EQ(database.Delete(int32, string), FAILED);
    EXPECT_EQ(database.Query(string, value, values), FAILED);
    EXPECT_EQ(database.ExecuteSql(string), FAILED);
    EXPECT_EQ(database.ExecuteAndGetLong(int64, string, strings), FAILED);
    EXPECT_EQ(database.Count(int64, string, value), FAILED);
    EXPECT_EQ(database.BeginTransaction(), FAILED);
    EXPECT_EQ(database.RollBack(), FAILED);
    EXPECT_EQ(database.Commit(), FAILED);
}

HWTEST_F(AppInfoDataBaseTest, DefaultConstructor, TestSize.Level1)
{
    VariantValue value{};
    EXPECT_EQ(value.GetType(), ValueType::TYPE_NULL);
    EXPECT_EQ(value.GetInt64(), -1);
    EXPECT_EQ(value.GetInt(), -1);
    EXPECT_TRUE(value.GetString().empty());
}

HWTEST_F(AppInfoDataBaseTest, Int32Constructor, TestSize.Level1)
{
    const int32_t testValue = -12345;
    VariantValue value{testValue};

    EXPECT_EQ(value.GetType(), ValueType::TYPE_INT);
    EXPECT_EQ(value.GetInt(), testValue);

    EXPECT_EQ(value.GetInt64(), -1);
    EXPECT_TRUE(value.GetString().empty());
}

HWTEST_F(AppInfoDataBaseTest, StringConstructor, TestSize.Level1)
{
    const std::string testValue = "test";
    VariantValue value{testValue};

    EXPECT_EQ(value.GetType(), ValueType::TYPE_STRING);
    EXPECT_EQ(value.GetString(), testValue);

    EXPECT_EQ(value.GetInt64(), -1);
    EXPECT_EQ(value.GetInt(), -1);
}

HWTEST_F(AppInfoDataBaseTest, emptyStringConstructor, TestSize.Level1)
{
    VariantValue value{std::string("")};

    EXPECT_EQ(value.GetType(), ValueType::TYPE_STRING);
    EXPECT_TRUE(value.GetString().empty());
}

HWTEST_F(AppInfoDataBaseTest, emptyInit, TestSize.Level1)
{
    GenericValues value;
    EXPECT_TRUE(value.GetAllKeys().empty());
    EXPECT_EQ(value.GetInt("any"), -1);
}

HWTEST_F(AppInfoDataBaseTest, IntegerVal, TestSize.Level1)
{
    GenericValues value;
    const std::string key = "security_level";
    const int32_t testInt = 65535;

    value.Put(key, testInt);
    EXPECT_EQ(value.GetInt(key), testInt);
}

HWTEST_F(AppInfoDataBaseTest, ComplexUsage, TestSize.Level1)
{
    GenericValues values;
    values.Put("counter", 1);
    values.Put("total", INT64_MAX);
    values.Put("serial", "88DF3A");

    EXPECT_TRUE(values.GetString("counter").empty());

    EXPECT_EQ(values.GetInt64("total"), INT64_MAX);
    EXPECT_EQ(values.GetInt("no_exist"), -1);
}

HWTEST_F(StatementTest, BindArg, TestSize.Level1)
{
    Statement stmt(db, "INSERT INFO test (name, value) VALUES (:name, :value)");

    EXPECT_EQ(stmt.GetParameterIndex(":name"), 0);
    stmt.Bind("name", VariantValue("dayn"));
    stmt.Bind("value", VariantValue(999));
    stmt.Step();
    stmt.Reset();
    stmt.Bind("name", VariantValue("another_name"));
    stmt.Step();
}

class SgSqliteHelperTest : public testing::Test {
protected:
    void SetUp() override
    {
        fs::remove_all(g_testDbDir);
        fs::create_directory(g_testDbDir);
        helper_ = CreateHelper();
    }

    std::shared_ptr<SgSqliteHelper> CreateHelper(int version = 1)
    {
        std::vector<std::string> createSqls = {
            "CREATE TABLE SecureLog(id INTEGER PRIMARY KEY, event TEXT, code INTEGER);"
        };
        return std::make_shared<SgSqliteHelper>(g_testDbName,
            g_testDbDir, version, createSqls);
    }

    void InsertSampleData()
    {
        const int32_t testValue = 1001;
        GenericValues val;
        val.Put("event", "login");
        val.Put("code", testValue);
        int64_t dummy;
        helper_->Insert(dummy, "SecureLog", val);
    }
    std::shared_ptr<SgSqliteHelper> helper_;
};

HWTEST_F(SgSqliteHelperTest, DatabaseInit, TestSize.Level1)
{
    auto helper = CreateHelper();
    auto stmt = helper->Prepare("SELECT name FROM sqlite_master WHERE type= 'table';");
    EXPECT_EQ(stmt.Step(), Statement::State::ROW);
    EXPECT_EQ(stmt.GetColumnString(0), "SecureLog");
}

HWTEST_F(SgSqliteHelperTest, InsertInvaildParam, TestSize.Level1)
{
    GenericValues emptyVal;
    int64_t rowId;

    EXPECT_EQ(helper_->Insert(rowId, "", emptyVal), SecurityGuard::FAILED);
    EXPECT_EQ(helper_->Insert(rowId, "SecureLog", GenericValues()), SecurityGuard::FAILED);
}

HWTEST_F(SgSqliteHelperTest, ConditionDel, TestSize.Level1)
{
    InsertSampleData();
    GenericValues cond;
    cond.Put("code_GE", 1000);
    cond.Put("event_LIKE", "%log%");

    int deleteCount = -1;
    EXPECT_EQ(helper_->Delete(deleteCount, "SecureLog", cond), SUCCESS);
}

HWTEST_F(SgSqliteHelperTest, BatchInsertData, TestSize.Level1)
{
    std::vector<GenericValues> batch;
    {
        GenericValues val1;
        val1.Put("code", 2001);
        val1.Put("event", "batch1");
        batch.emplace_back(val1);

        GenericValues val2;
        val2.Put("event", "batch2");
        val2.Put("code", 2002);
        batch.emplace_back(val2);
    }
    int64_t count;
    EXPECT_EQ(helper_->BatchInsert(count, "SecureLog", batch), 0);
}

HWTEST_F(SgSqliteHelperTest, QueryCondtion, TestSize.Level1)
{
    GenericValues cond;
    cond.Put("code_IN", "1000, 1001, 1002");
    cond.Put("event_LIKE", "critical%");

    std::vector<GenericValues> results;
    EXPECT_EQ(helper_->Query("SecureLog", cond, results), SUCCESS);
}

HWTEST_F(SgSqliteHelperTest, TransactionInter, TestSize.Level1)
{
    helper_->BeginTransaction();
    InsertSampleData();
    helper_->RollbackTransaction();

    Statement stmt = helper_->Prepare("SELECT COUNT(*) FROM SecureLog");
    stmt.Step();
    EXPECT_EQ(stmt.GetColumnInt(0), 0);
}

HWTEST_F(SgSqliteHelperTest, Covery, TestSize.Level1)
{
    GenericValues val;
    int64_t maxVal = INT64_MAX;
    val.Put("code", maxVal);
    val.Put("event", "max_value");

    std::vector<GenericValues> vals;
    std::vector<uint8_t> dest;
    int64_t int64;
    int rowId;

    EXPECT_EQ(helper_->BatchInsert(int64, "SecureLog", vals), SUCCESS);
    EXPECT_EQ(helper_->Update(rowId, "SecureLog", val), SUCCESS);
    EXPECT_EQ(helper_->Attach("", "SecureLog", dest), SUCCESS);
    Statement stmt = helper_->Prepare("SELECT code FROM SecureLog WHERE event='max_value'");
    stmt.Step();
    EXPECT_EQ(stmt.GetColumnInt64(0), 0);
}

HWTEST_F(SgSqliteHelperTest, ExecuteGetLong, TestSize.Level1)
{
    int64_t val = 0;
    std::vector<std::string> bindArgs;
    EXPECT_EQ(helper_->ExecuteAndGetLong(val, "", bindArgs), 1);
}

HWTEST_F(SgSqliteHelperTest, TestBuildSql, TestSize.Level1)
{
    helper_->OnUpdate();
    GenericValues val{};
    std::vector<std::string> bindArgs;
    EXPECT_TRUE(helper_->BuildUpdateSql("SecureLog", val, "").empty());
    EXPECT_TRUE(helper_->BuildInsertSql("SecureLog", val).empty());
}

HWTEST_F(SgSqliteHelperTest, TestEndWith, TestSize.Level1)
{
    EXPECT_TRUE(!helper_->EndWith("", "sec"));
}

HWTEST_F(SgSqliteHelperTest, TestBuild, TestSize.Level1)
{
    GenericValues val;
    val.Put("code", 2222);
    val.Put("event", "concurent");
    EXPECT_FALSE(helper_->BuildUpdateSql("SecureLog", val, "").empty());

    QueryOptions options;
    options.orderBy = "Id DESC";
    options.limit = 2;
    EXPECT_FALSE(helper_->BuildSelectSql("SecureLog", val, options).empty());
}

HWTEST_F(SgSqliteHelperTest, TestStatement, TestSize.Level1)
{
    sqlite3* db = nullptr;
    Statement stmt(db, "");
    stmt.Bind(1, "111");
    stmt.Bind(1, 111);
    int64_t val = 0;
    stmt.Bind(1, val);
    EXPECT_NE(stmt.Step(), Statement::State::ROW);
}
}