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

#include "security_guard_test.h"

#include <vector>
#include <nlohmann/json.hpp>
#include <gmock/gmock.h>
#include <thread>

#include "data_mgr_cfg.h"
#include "model_cfg_marshalling.h"
#include "event_config.h"
#include "model_analysis.h"
#include "security_guard_define.h"
#include "model_config.h"
#include "threat_config.h"
#include "security_guard_log.h"
#include "base_event_id.h"
#include "data_storage.h"
#include "i_collect_info.h"
#include "database.h"
#include "data_manager.h"
#include "database_wrapper.h"
#include "task_manager.h"
#include "database_manager.h"
#include "data_format.h"

using nlohmann::json;
using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityGuardTest;
using namespace OHOS::DistributedKv;

namespace OHOS::Security::SecurityGuardTest {
namespace {
    constexpr uint32_t MAX_PUSH_NUM = 6;
    const std::string TEST_APP_ID = "test_security_guard";
    const std::string TEST_STORE_ID = "test_store_id";
}

void SecurityGuardUnitTest::SetUpTestCase()
{
}

void SecurityGuardUnitTest::TearDownTestCase()
{
}

void SecurityGuardUnitTest::SetUp()
{
}

void SecurityGuardUnitTest::TearDown()
{
}

class MockDataStorage : public DataStorage {
public:
    explicit MockDataStorage(std::shared_ptr<DatabaseWrapper> &database) : DataStorage(database) {}
    ~MockDataStorage() override = default;
    MOCK_METHOD1(LoadAllData, ErrorCode(std::map<std::string, std::shared_ptr<ICollectInfo>> &infos));
    MOCK_METHOD1(AddCollectInfo, ErrorCode(const ICollectInfo &info));
    MOCK_METHOD2(SaveEntries, void(const std::vector<OHOS::DistributedKv::Entry> &allEntries,
        std::map<std::string, std::shared_ptr<ICollectInfo>> &infos));
    MOCK_METHOD2(GetCollectInfoById, ErrorCode(const std::string &id, ICollectInfo &info));
};

class MockCollectInfo : public ICollectInfo {
public:
    ~MockCollectInfo() override = default;
    MOCK_CONST_METHOD1(ToJson, void(json &jsonObj));
    MOCK_METHOD1(FromJson, void(const json &jsonObj));
    MOCK_CONST_METHOD0(ToString, std::string());
    MOCK_CONST_METHOD0(GetPrimeKey, std::string());
};

class MockDatabase : public Database {
public:
    explicit MockDatabase(std::shared_ptr<DatabaseManager> dataManager) : Database(dataManager) {}
    MOCK_METHOD2(GetEntries, Status(const OHOS::DistributedKv::Key &key, std::vector<Entry> &entries));
    MOCK_METHOD2(Get, Status(const OHOS::DistributedKv::Key &key, OHOS::DistributedKv::Value &value));
    MOCK_METHOD2(Put, Status(const OHOS::DistributedKv::Key &key, const OHOS::DistributedKv::Value &value));
    MOCK_METHOD1(Delete, Status(const OHOS::DistributedKv::Key &key));
};

class MockDatabaseManager : public DatabaseManager {
public:
    explicit MockDatabaseManager(const DistributedKvDataManager &dataManager) : DatabaseManager(dataManager) {}
    MOCK_METHOD4(GetSingleKvStore, Status(const Options &options, const AppId &appId, const StoreId &storeId,
        std::shared_ptr<SingleKvStore> &singleKvStore));
    MOCK_METHOD2(CloseKvStore, Status(const AppId &appId, std::shared_ptr<SingleKvStore> &kvStore));
    MOCK_METHOD2(DeleteKvStore, Status(const AppId &appId, const StoreId &storeId));
};

/**
 * @tc.name: TestDataMgrCfg001
 * @tc.desc: Test DataMgrCfg setter and getter
 * @tc.type: FUNC
 * @tc.require: SR000H8DA6
 */
HWTEST_F(SecurityGuardUnitTest, TestDataMgrCfg001, TestSize.Level1)
{
    static const uint32_t actualValue = 1;
    DataMgrCfg::GetInstance().SetEventMaxRamNum(actualValue);
    DataMgrCfg::GetInstance().SetDeviceRam(actualValue);
    DataMgrCfg::GetInstance().SetDeviceRom(actualValue);
    DataMgrCfg::GetInstance().SetEventMaxRomNum(actualValue);
    uint32_t expectValue = DataMgrCfg::GetInstance().GetEventMaxRamNum();
    EXPECT_EQ(expectValue, actualValue);
    expectValue = DataMgrCfg::GetInstance().GetDeviceRam();
    EXPECT_EQ(expectValue, actualValue);
    expectValue = DataMgrCfg::GetInstance().GetDeviceRom();
    EXPECT_EQ(expectValue, actualValue);
    expectValue = DataMgrCfg::GetInstance().GetEventMaxRomNum();
    EXPECT_EQ(expectValue, actualValue);
}

/**
 * @tc.name: TestEventConfig001
 * @tc.desc: Test EventConfig getter
 * @tc.type: FUNC
 * @tc.require: SR000H8DA6
 */
HWTEST_F(SecurityGuardUnitTest, TestEventConfig001, TestSize.Level1)
{
    EventCfgSt config = {
        .eventId = 000000001,
        .eventName = "test eventId",
        .version = 1,
        .eventType = 1,
        .dataSensitivityLevel = 1,
        .storageRamNums = 1,
        .storageRomNums = 5
    };
    std::shared_ptr<EventConfig> eventConfig = std::make_shared<EventConfig>(config);
    EXPECT_EQ(eventConfig->GetEventId(), config.eventId);
    EXPECT_EQ(eventConfig->GetEventType(), config.eventType);
    EXPECT_STREQ(eventConfig->GetEventName().c_str(), config.eventName.c_str());
    EXPECT_EQ(eventConfig->GetVersion(), config.version);
    EXPECT_EQ(eventConfig->GetDataSensitivityLevel(), config.dataSensitivityLevel);
    EXPECT_EQ(eventConfig->GetStorageRamNums(), config.storageRamNums);
    EXPECT_EQ(eventConfig->GetStorageRomNums(), config.storageRomNums);
}

/**
 * @tc.name: TestModelConfig001
 * @tc.desc: Test ModelConfig getter
 * @tc.type: FUNC
 * @tc.require: SR000H8DA6
 */
HWTEST_F(SecurityGuardUnitTest, TestModelConfig001, TestSize.Level1)
{
    ModelCfgSt config = {
        .modelId = 3001000000,
        .modelName = "test modelId",
        .version = 1,
        .threatList = {},
        .computeModel = ""
    };
    std::shared_ptr<ModelConfig> modelConfig = std::make_shared<ModelConfig>(config);
    EXPECT_EQ(modelConfig->GetModelId(), config.modelId);
    EXPECT_STREQ(modelConfig->GetModelName().c_str(), config.modelName.c_str());
    EXPECT_EQ(modelConfig->GetVersion(), config.version);
    std::vector<uint32_t> vec = modelConfig->GetThreatList();
    EXPECT_TRUE(vec.empty());
    EXPECT_EQ(modelConfig->GetComputeModel(), config.computeModel);
}

/**
 * @tc.name: TestThreatConfig001
 * @tc.desc: Test ThreatConfig getter
 * @tc.type: FUNC
 * @tc.require: SR000H8DA6
 */
HWTEST_F(SecurityGuardUnitTest, TestThreatConfig001, TestSize.Level1)
{
    ThreatCfgSt config = {
        .threatId = 3000000000,
        .threatName = "test threatId",
        .version = 1,
        .eventList = {},
        .computeModel = ""
    };
    std::shared_ptr<ThreatConfig> threatConfig = std::make_shared<ThreatConfig>(config);
    EXPECT_EQ(threatConfig->GetThreatId(), config.threatId);
    EXPECT_STREQ(threatConfig->GetThreatName().c_str(), config.threatName.c_str());
    EXPECT_EQ(threatConfig->GetVersion(), config.version);
    std::vector<int64_t> vec = threatConfig->GetEventList();
    EXPECT_TRUE(vec.empty());
    EXPECT_EQ(threatConfig->GetComputeModel(), config.computeModel);
}

/**
 * @tc.name: TestModelAnalysis001
 * @tc.desc: Test ModelAnalysis GetEventIds and GetEventConfig
 * @tc.type: FUNC
 * @tc.require: SR000H8DA6
 */
HWTEST_F(SecurityGuardUnitTest, TestModelAnalysis001, TestSize.Level1)
{
    ErrorCode code = ModelAnalysis::GetInstance().AnalyseModel();
    EXPECT_EQ(code, ErrorCode::SUCCESS);

    uint32_t modelId = 0;
    std::vector<int64_t> vec;
    vec = ModelAnalysis::GetInstance().GetEventIds(modelId);
    EXPECT_TRUE(vec.empty());

    modelId = 3001000000;
    vec = ModelAnalysis::GetInstance().GetEventIds(modelId);
    EXPECT_FALSE(vec.empty());

    std::shared_ptr<EventConfig> eventConfig = std::make_shared<EventConfig>();
    int64_t eventId = 0;
    code = ModelAnalysis::GetInstance().GetEventConfig(eventId, eventConfig);
    EXPECT_NE(code, ErrorCode::SUCCESS);

    eventId = 1011009000;
    code = ModelAnalysis::GetInstance().GetEventConfig(eventId, eventConfig);
    EXPECT_EQ(code, ErrorCode::SUCCESS);
    EXPECT_EQ(eventConfig->GetEventId(), eventId);
}

/**
 * @tc.name: TestBaseEventId001
 * @tc.desc: Test BaseEventId class
 * @tc.type: FUNC
 * @tc.require: SR000H8DA6
 */
HWTEST_F(SecurityGuardUnitTest, TestBaseEventId001, TestSize.Level1)
{
    ErrorCode code = ModelAnalysis::GetInstance().AnalyseModel();
    EXPECT_EQ(code, ErrorCode::SUCCESS);

    BaseEventId fakeEventId(0);
    EventDataSt eventData = {
        .eventId = 1011009000,
        .version = "0",
        .date = "test date",
        .content = "test content"
    };
    bool isSuccess = fakeEventId.Push(eventData);
    EXPECT_FALSE(isSuccess);

    std::vector<EventDataSt> eventDataVec;
    isSuccess = fakeEventId.GetCacheData(eventDataVec);
    EXPECT_FALSE(isSuccess);

    eventData.eventId = 0;
    isSuccess = fakeEventId.Push(eventData);
    EXPECT_FALSE(isSuccess);

    BaseEventId eventId(1011009000);
    eventData.eventId = 1011009000;
    eventDataVec = eventId.GetEventVec();
    EXPECT_TRUE(eventDataVec.empty());

    isSuccess = eventId.Push(eventData);
    EXPECT_TRUE(isSuccess);
    isSuccess = eventId.GetCacheData(eventDataVec);
    EXPECT_FALSE(eventDataVec.empty());
    EXPECT_TRUE(isSuccess);

    for (uint32_t index = 0; index < MAX_PUSH_NUM; index++) {
        isSuccess = eventId.Push(eventData);
        EXPECT_TRUE(isSuccess);
    }

    isSuccess = eventId.GetCacheData(eventDataVec);
    EXPECT_FALSE(eventDataVec.empty());
    EXPECT_TRUE(isSuccess);

    eventDataVec = eventId.GetEventVec();
    EXPECT_FALSE(eventDataVec.empty());

    std::string stringOri = eventId.ToString();
    json jsonObj;
    eventId.ToJson(jsonObj);
    eventId.FromJson(jsonObj);
    std::string string = eventId.ToString();
    EXPECT_STREQ(string.c_str(), stringOri.c_str());
}

/**
 * @tc.name: TestBaseEventIdStorage001
 * @tc.desc: Test BaseEventIdStorage class with mock
 * @tc.type: FUNC
 * @tc.require: SR000H8DA6
 */
HWTEST_F(SecurityGuardUnitTest, TestBaseEventIdStorage001, TestSize.Level1)
{
    DistributedKvDataManager kvDataManager;
    std::shared_ptr<DatabaseManager> dataManager = std::make_shared<DatabaseManager>(kvDataManager);
    std::shared_ptr<Database> database = std::make_shared<Database>(dataManager);
    std::shared_ptr<DatabaseWrapper> databaseWrapper;
    std::shared_ptr<DataStorage> storage = std::make_shared<BaseEventIdStorage>(databaseWrapper);
    std::map<std::string, std::shared_ptr<ICollectInfo>> infos;

    // database wrapper is null
    ErrorCode code = storage->LoadAllData(infos);
    EXPECT_EQ(code, NULL_OBJECT);
    EXPECT_TRUE(infos.empty());
    MockCollectInfo info;
    EXPECT_CALL(info, ToString).Times(AtLeast(1)).WillOnce(Return("")).WillRepeatedly(Return("TEST STRING"));
    EXPECT_CALL(info, GetPrimeKey).Times(AtLeast(1)).WillOnce(Return("")).WillRepeatedly(Return("TEST KEY"));
    code = storage->AddCollectInfo(info);
    EXPECT_EQ(code, DB_INFO_ERR);
    code = storage->AddCollectInfo(info);
    EXPECT_EQ(code, NULL_OBJECT);

    code = storage->GetCollectInfoById("TEST KEY", info);
    EXPECT_EQ(code, NULL_OBJECT);

    // database wrapper is not null
    auto mockDatabase = std::make_shared<MockDatabase>(dataManager);
    EXPECT_CALL(*mockDatabase, GetEntries).Times(AtLeast(1)).WillRepeatedly(Return(Status::DB_ERROR));
    EXPECT_CALL(*mockDatabase, Get).Times(AtLeast(1)).WillRepeatedly(Return(Status::DB_ERROR));
    EXPECT_CALL(*mockDatabase, Put).Times(AtLeast(1)).WillRepeatedly(Return(Status::DB_ERROR));
    databaseWrapper = std::make_shared<DatabaseWrapper>(mockDatabase);
    auto storageObj = BaseEventIdStorage(databaseWrapper);
    code = storageObj.LoadAllData(infos);
    EXPECT_EQ(code, DB_LOAD_ERR);
    EXPECT_TRUE(infos.empty());
    EXPECT_CALL(info, ToString).Times(AtLeast(1)).WillOnce(Return("")).WillRepeatedly(Return("TEST STRING"));
    EXPECT_CALL(info, GetPrimeKey).Times(AtLeast(1)).WillOnce(Return("")).WillRepeatedly(Return("TEST KEY"));
    code = storageObj.AddCollectInfo(info);
    EXPECT_EQ(code, DB_INFO_ERR);
    code = storageObj.AddCollectInfo(info);
    EXPECT_EQ(code, DB_OPT_ERR);

    code = storageObj.GetCollectInfoById("TEST KEY", info);
    EXPECT_EQ(code, DB_OPT_ERR);
}

/**
 * @tc.name: TestDataFormat001
 * @tc.desc: Test DataFormat class with all type
 * @tc.type: FUNC
 * @tc.require: SR000H8DA6
 */
HWTEST_F(SecurityGuardUnitTest, TestDataFormat001, TestSize.Level1)
{
    string test = "test";
    string content;
    bool isSuccess = DataFormat::CheckRiskContent(content);
    EXPECT_FALSE(isSuccess);

    static const uint32_t maxLoop = 250;
    for (uint32_t i = 0; i < maxLoop; i++) {
        content += test;
    }
    isSuccess = DataFormat::CheckRiskContent(content);
    EXPECT_FALSE(isSuccess);

    content = "{\"cred\":1,\"extra\":\"\",\"status\":\"0\"}";
    isSuccess = DataFormat::CheckRiskContent(content);
    EXPECT_FALSE(isSuccess);

    content = "{\"cred\":\"1\",\"extra\":\"\",\"status\":0}";
    isSuccess = DataFormat::CheckRiskContent(content);
    EXPECT_FALSE(isSuccess);

    content = "{\"cred\":1,\"extra\":1,\"status\":0}";
    isSuccess = DataFormat::CheckRiskContent(content);
    EXPECT_FALSE(isSuccess);

    content = "{\"cred\":1,\"extra\":\"\",\"status\":0}";
    isSuccess = DataFormat::CheckRiskContent(content);
    EXPECT_TRUE(isSuccess);
}

/**
 * @tc.name: TestDataManager001
 * @tc.desc: Test DataManager class with nullptr
 * @tc.type: FUNC
 * @tc.require: SR000H8DA6
 */
HWTEST_F(SecurityGuardUnitTest, TestDataManager001, TestSize.Level1)
{
    ErrorCode code = ModelAnalysis::GetInstance().AnalyseModel();
    EXPECT_EQ(code, ErrorCode::SUCCESS);

    DistributedKvDataManager kvDataManager;
    std::shared_ptr<DatabaseManager> dataManager = std::make_shared<DatabaseManager>(kvDataManager);
    std::shared_ptr<Database> database = std::make_shared<MockDatabase>(dataManager);
    std::shared_ptr<DatabaseWrapper> databaseWrapper = std::make_shared<DatabaseWrapper>(database);
    std::shared_ptr<DataStorage> storage;
    MockCollectInfo info;
    std::vector<int64_t> eventIds;
    std::vector<EventDataSt> eventDataSt;

    // test storage is null
    EventDataSt eventData = {
        .eventId = 1011009000,
        .version = "0",
        .date = "test date",
        .content = "test content"
    };
    std::shared_ptr<DataManager> manager = std::make_shared<DataManager>(storage);
    code = manager->LoadCacheData();
    EXPECT_EQ(code, NULL_OBJECT);
    code = manager->AddCollectInfo(eventData);
    EXPECT_EQ(code, NULL_OBJECT);
    code = manager->GetCollectInfoById("test", info);
    EXPECT_EQ(code, NULL_OBJECT);
    code = manager->GetEventDataById(eventIds, eventDataSt);
    EXPECT_EQ(code, NULL_OBJECT);
    code = manager->GetCachedEventDataById(eventIds, eventDataSt);
    EXPECT_EQ(code, ErrorCode::SUCCESS);
}

/**
 * @tc.name: TestDataManager002
 * @tc.desc: Test DataManager class with mock
 * @tc.type: FUNC
 * @tc.require: SR000H8DA6
 */
HWTEST_F(SecurityGuardUnitTest, TestDataManager002, TestSize.Level1)
{
    ErrorCode code = ModelAnalysis::GetInstance().AnalyseModel();
    EXPECT_EQ(code, ErrorCode::SUCCESS);

    DistributedKvDataManager kvDataManager;
    std::shared_ptr<DatabaseManager> dataManager = std::make_shared<DatabaseManager>(kvDataManager);
    std::shared_ptr<Database> database = std::make_shared<MockDatabase>(dataManager);
    std::shared_ptr<DatabaseWrapper> databaseWrapper = std::make_shared<DatabaseWrapper>(database);
    std::shared_ptr<DataStorage> storage;
    MockCollectInfo info;
    std::vector<int64_t> eventIds;
    std::vector<EventDataSt> eventDataSt;
    EventDataSt eventData = {
        .eventId = 1011009000,
        .version = "0",
        .date = "test date",
        .content = "test content"
    };

    // test storage is not null
    auto mockStorage = std::make_shared<MockDataStorage>(databaseWrapper);
    EXPECT_CALL(*mockStorage, LoadAllData).Times(AtLeast(1)).WillOnce(Return(FAILED)).WillOnce(
        Return(FAILED)).WillRepeatedly(Return(ErrorCode::SUCCESS));
    EXPECT_CALL(*mockStorage, AddCollectInfo).Times(AtLeast(1)).WillOnce(Return(FAILED)).WillRepeatedly(
        Return(ErrorCode::SUCCESS));
    EXPECT_CALL(*mockStorage, GetCollectInfoById).Times(AtLeast(1)).WillOnce(Return(FAILED)).WillRepeatedly(
        Return(ErrorCode::SUCCESS));
    std::map<std::string, std::shared_ptr<ICollectInfo>> infos;
    EXPECT_CALL(*mockStorage, SaveEntries).WillRepeatedly(
        [&infos](const std::vector<OHOS::DistributedKv::Entry> &allEntries,
            std::map<std::string, std::shared_ptr<ICollectInfo>> &info) {
            infos = info;
        });
    DataManager managerObj(mockStorage);
    code = managerObj.LoadCacheData();
    EXPECT_EQ(code, FAILED);
    code = managerObj.LoadCacheData();
    EXPECT_EQ(code, FAILED);

    code = managerObj.AddCollectInfo(eventData);
    EXPECT_EQ(code, ErrorCode::FAILED);
    code = managerObj.AddCollectInfo(eventData);
    EXPECT_EQ(code, ErrorCode::SUCCESS);

    code = managerObj.GetCollectInfoById("test", info);
    EXPECT_EQ(code, ErrorCode::SUCCESS);

    code = managerObj.GetEventDataById(eventIds, eventDataSt);
    EXPECT_EQ(code, ErrorCode::FAILED);
    eventIds.emplace_back(-1);
    code = managerObj.GetEventDataById(eventIds, eventDataSt);
    EXPECT_EQ(code, ErrorCode::SUCCESS);

    code = managerObj.GetCachedEventDataById(eventIds, eventDataSt);
    EXPECT_EQ(code, ErrorCode::SUCCESS);
    eventIds.clear();
    eventIds.emplace_back(1011009000);
    code = managerObj.GetCachedEventDataById(eventIds, eventDataSt);
    EXPECT_EQ(code, ErrorCode::SUCCESS);
}

/**
 * @tc.name: TestDatabase001
 * @tc.desc: Test Database class with invalid argument
 * @tc.type: FUNC
 * @tc.require: SR000H8DA6
 */
HWTEST_F(SecurityGuardUnitTest, TestDatabase001, TestSize.Level1)
{
    DistributedKvDataManager kvDataManager;
    std::shared_ptr<MockDatabaseManager> dataManager = std::make_shared<MockDatabaseManager>(kvDataManager);
    std::shared_ptr<Database> database = std::make_shared<Database>(dataManager);

    OHOS::DistributedKv::Key key;
    OHOS::DistributedKv::Value value;
    std::vector<Entry> entries;
    Status status;

    EXPECT_CALL(*dataManager, GetSingleKvStore).Times(AtLeast(1)).WillRepeatedly(Return(Status::DB_ERROR));
    status = database->GetEntries(key, entries);
    EXPECT_EQ(status, Status::INVALID_ARGUMENT);
    status = database->Get(key, value);
    EXPECT_EQ(status, Status::INVALID_ARGUMENT);
    status = database->Put(key, value);
    EXPECT_EQ(status, Status::INVALID_ARGUMENT);
    status = database->Delete(key);
    EXPECT_EQ(status, Status::INVALID_ARGUMENT);
    status = database->DeleteKvStore();
    EXPECT_EQ(status, Status::INVALID_ARGUMENT);
}

/**
 * @tc.name: TestDatabaseWrapper001
 * @tc.desc: Test DatabaseWrapper class with mock
 * @tc.type: FUNC
 * @tc.require: SR000H8DA6
 */
HWTEST_F(SecurityGuardUnitTest, TestDatabaseWrapper001, TestSize.Level1)
{
    DistributedKvDataManager kvDataManager;
    std::shared_ptr<MockDatabaseManager> dataManager = std::make_shared<MockDatabaseManager>(kvDataManager);
    std::shared_ptr<Database> database;
    DatabaseWrapper databaseWrapper(database);
    OHOS::DistributedKv::Key key;
    OHOS::DistributedKv::Value value;
    std::vector<Entry> entries;
    Status status;

    status = databaseWrapper.GetEntries(key, entries);
    EXPECT_EQ(status, Status::INVALID_ARGUMENT);
    status = databaseWrapper.Get(key, value);
    EXPECT_EQ(status, Status::INVALID_ARGUMENT);
    status = databaseWrapper.Put(key, value);
    EXPECT_EQ(status, Status::INVALID_ARGUMENT);
    status = databaseWrapper.Delete(key);
    EXPECT_EQ(status, Status::INVALID_ARGUMENT);

    auto mockDatabase = std::make_shared<MockDatabase>(dataManager);
    EXPECT_CALL(*mockDatabase, GetEntries).Times(AtLeast(1)).WillRepeatedly(Return(Status::DB_ERROR));
    EXPECT_CALL(*mockDatabase, Get).Times(AtLeast(1)).WillOnce(Return(Status::DB_ERROR)).WillRepeatedly(
        Return(Status::SUCCESS));
    EXPECT_CALL(*mockDatabase, Put).Times(AtLeast(1)).WillRepeatedly(Return(Status::DB_ERROR));
    EXPECT_CALL(*mockDatabase, Delete).Times(AtLeast(1)).WillRepeatedly(Return(Status::DB_ERROR));
    DatabaseWrapper databaseWrapperObj(mockDatabase);
    status = databaseWrapperObj.GetEntries(key, entries);
    EXPECT_EQ(status, Status::DB_ERROR);
    status = databaseWrapperObj.Get(key, value);
    EXPECT_EQ(status, Status::DB_ERROR);
    status = databaseWrapperObj.Put(key, value);
    EXPECT_EQ(status, Status::DB_ERROR);
    status = databaseWrapperObj.Delete(key);
    EXPECT_EQ(status, Status::DB_ERROR);
}
}
