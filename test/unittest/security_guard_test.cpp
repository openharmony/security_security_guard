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
#include <poll.h>
#include <sys/socket.h>

#include "file_ex.h"
#include "securec.h"
#include "string_ex.h"

#include "data_mgr_cfg.h"
#include "model_cfg_marshalling.h"
#include "event_config.h"
#include "model_analysis.h"
#include "security_guard_define.h"
#include "model_config.h"
#include "threat_config.h"
#include "security_guard_utils.h"
#include "base_event_id.h"
#include "data_storage.h"
#include "i_collect_info.h"
#include "database.h"
#include "data_manager.h"
#include "data_manager_wrapper.h"
#include "database_wrapper.h"
#include "database_manager.h"
#include "data_format.h"
#include "json_cfg.h"
#include "kernel_interface_adapter.h"
#include "data_collect_manager_service.h"
#include "risk_analysis_manager_service.h"
#include "risk_analysis_model.h"
#include "i_data_collect_manager.h"
#include "model_manager.h"
#include "uevent_listener.h"
#include "uevent_listener_impl.h"
#include "uevent_notify.h"

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
    SaveStringToFile("/sys/fs/selinux/enforce", "0");
}

void SecurityGuardUnitTest::TearDownTestCase()
{
    SaveStringToFile("/sys/fs/selinux/enforce", "1");
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
    ~MockDatabase() override = default;
    MOCK_METHOD2(GetEntries, Status(const OHOS::DistributedKv::Key &key, std::vector<Entry> &entries));
    MOCK_METHOD2(Get, Status(const OHOS::DistributedKv::Key &key, OHOS::DistributedKv::Value &value));
    MOCK_METHOD2(Put, Status(const OHOS::DistributedKv::Key &key, const OHOS::DistributedKv::Value &value));
    MOCK_METHOD1(Delete, Status(const OHOS::DistributedKv::Key &key));
    MOCK_METHOD0(DeleteKvStore, Status());
};

class MockDatabaseManager : public DatabaseManager {
public:
    explicit MockDatabaseManager(const DistributedKvDataManager &dataManager) : DatabaseManager(dataManager) {}
    ~MockDatabaseManager() override = default;
    MOCK_METHOD4(GetSingleKvStore, Status(const Options &options, const AppId &appId, const StoreId &storeId,
        std::shared_ptr<SingleKvStore> &singleKvStore));
    MOCK_METHOD2(CloseKvStore, Status(const AppId &appId, std::shared_ptr<SingleKvStore> &kvStore));
    MOCK_METHOD2(DeleteKvStore, Status(const AppId &appId, const StoreId &storeId));
};

class MockUeventListenerImpl : public UeventListenerImpl {
public:
    explicit MockUeventListenerImpl(KernelInterfaceAdapter adapter) : UeventListenerImpl(adapter) {}
    ~MockUeventListenerImpl() override = default;
    MOCK_METHOD0(InitUevent, bool());
    MOCK_METHOD2(UeventListen, int(char *buffer, size_t length));
    MOCK_METHOD2(ParseEvent, void(char *buffer, size_t length));
};

class MockKernelInterfaceAdapter : public KernelInterfaceAdapter {
public:
    MockKernelInterfaceAdapter() = default;
    ~MockKernelInterfaceAdapter() override = default;
    MOCK_METHOD3(Socket, int(int af, int type, int protocol));
    MOCK_METHOD3(Bind, int(int fd, const struct sockaddr* addr, socklen_t addrLength));
    MOCK_METHOD3(Poll, int(struct pollfd* const fds, nfds_t fdCount, int timeout));
    MOCK_METHOD4(Recv, ssize_t(int socket, void* const buf, size_t len, int flags));
    MOCK_METHOD2(Open, int(const char* const pathName, int flags));
    MOCK_METHOD3(Write, ssize_t(int fd, const void* const buf, size_t count));
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
 * @tc.desc: Test ModelAnalysis GetEventIds and GetModelConfig
 * @tc.type: FUNC
 * @tc.require: SR000H8DA6
 */
HWTEST_F(SecurityGuardUnitTest, TestModelAnalysis001, TestSize.Level1)
{
    std::vector<int64_t> vec = ModelAnalysis::GetInstance().GetAllEventIds();
    EXPECT_TRUE(vec.empty());
    ErrorCode code = ModelAnalysis::GetInstance().AnalyseModel();
    EXPECT_EQ(code, ErrorCode::SUCCESS);
    vec = ModelAnalysis::GetInstance().GetAllEventIds();
    EXPECT_FALSE(vec.empty());

    uint32_t modelId = 0;
    vec = ModelAnalysis::GetInstance().GetEventIds(modelId);
    EXPECT_TRUE(vec.empty());
    ModelCfgSt modelSt = {
        .modelId = 3001000000,
        .modelName = "test modelId",
        .version = 1,
        .threatList = {},
        .computeModel = ""
    };
    auto modelConfig = std::make_shared<ModelConfig>(modelSt);
    code = ModelAnalysis::GetInstance().GetModelConfig(modelId, modelConfig);
    EXPECT_NE(code, ErrorCode::SUCCESS);

    modelId = 3001000000;
    vec = ModelAnalysis::GetInstance().GetEventIds(modelId);
    EXPECT_FALSE(vec.empty());
    code = ModelAnalysis::GetInstance().GetModelConfig(modelId, modelConfig);
    EXPECT_EQ(code, ErrorCode::SUCCESS);
}

/**
 * @tc.name: TestModelAnalysis002
 * @tc.desc: Test ModelAnalysis GetEventIds and GetEventConfig
 * @tc.type: FUNC
 * @tc.require: SR000H8DA6
 */
HWTEST_F(SecurityGuardUnitTest, TestModelAnalysis002, TestSize.Level1)
{
    EventCfgSt eventSt = {
        .eventId = 000000001,
        .eventName = "test eventId",
        .version = 1,
        .eventType = 1,
        .dataSensitivityLevel = 1,
        .storageRamNums = 1,
        .storageRomNums = 5
    };
    auto eventConfig = std::make_shared<EventConfig>(eventSt);
    int64_t eventId = 0;
    ErrorCode code = ModelAnalysis::GetInstance().GetEventConfig(eventId, eventConfig);
    EXPECT_NE(code, ErrorCode::SUCCESS);

    eventId = 1011009000;
    code = ModelAnalysis::GetInstance().GetEventConfig(eventId, eventConfig);
    EXPECT_EQ(code, ErrorCode::SUCCESS);
    EXPECT_EQ(eventConfig->GetEventId(), eventId);
}

/**
 * @tc.name: TestModelAnalysis003
 * @tc.desc: Test ModelAnalysis GetThreatConfig
 * @tc.type: FUNC
 * @tc.require: SR000H8DA6
 */
HWTEST_F(SecurityGuardUnitTest, TestModelAnalysis003, TestSize.Level1)
{
    ThreatCfgSt threatSt = {
        .threatId = 3000000000,
        .threatName = "test threatId",
        .version = 1,
        .eventList = {},
        .computeModel = ""
    };
    auto threatConfig = std::make_shared<ThreatConfig>(threatSt);
    uint32_t threatId = 0;
    ErrorCode code = ModelAnalysis::GetInstance().GetThreatConfig(threatId, threatConfig);
    EXPECT_NE(code, ErrorCode::SUCCESS);

    threatId = 3000000000;
    code = ModelAnalysis::GetInstance().GetThreatConfig(threatId, threatConfig);
    EXPECT_EQ(code, ErrorCode::SUCCESS);
    EXPECT_EQ(threatConfig->GetThreatId(), threatId);
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
 * @tc.name: TestDataFormat002
 * @tc.desc: Test ParseEventList with all type
 * @tc.type: FUNC
 * @tc.require: SR000H8DA6
 */
HWTEST_F(SecurityGuardUnitTest, TestDataFormat002, TestSize.Level1)
{
    std::string eventList = "test";
    std::vector<int64_t> eventListVec;
    ErrorCode code = DataFormat::ParseEventList(eventList, eventListVec);
    EXPECT_EQ(code, JSON_ERR);
    eventList = "{\"eventIds\":[1]}";
    code = DataFormat::ParseEventList(eventList, eventListVec);
    EXPECT_EQ(code, JSON_ERR);
    eventList = "{\"eventId\":1}";
    code = DataFormat::ParseEventList(eventList, eventListVec);
    EXPECT_EQ(code, JSON_ERR);
    eventList = "{\"eventId\":[\"a\"]}";
    code = DataFormat::ParseEventList(eventList, eventListVec);
    EXPECT_EQ(code, FAILED);
    eventList = "{\"eventId\":[1]}";
    code = DataFormat::ParseEventList(eventList, eventListVec);
    EXPECT_EQ(code, ErrorCode::SUCCESS);
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
    status = databaseWrapper.DeleteKvStore();
    EXPECT_EQ(status, Status::INVALID_ARGUMENT);

    auto mockDatabase = std::make_shared<MockDatabase>(dataManager);
    EXPECT_CALL(*mockDatabase, GetEntries).Times(AtLeast(1)).WillRepeatedly(Return(Status::DB_ERROR));
    EXPECT_CALL(*mockDatabase, Get).Times(AtLeast(1)).WillOnce(Return(Status::DB_ERROR)).WillRepeatedly(
        Return(Status::SUCCESS));
    EXPECT_CALL(*mockDatabase, Put).Times(AtLeast(1)).WillRepeatedly(Return(Status::DB_ERROR));
    EXPECT_CALL(*mockDatabase, Delete).Times(AtLeast(1)).WillRepeatedly(Return(Status::DB_ERROR));
    EXPECT_CALL(*mockDatabase, DeleteKvStore).Times(AtLeast(1)).WillRepeatedly(Return(Status::DB_ERROR));
    DatabaseWrapper databaseWrapperObj(mockDatabase);
    status = databaseWrapperObj.GetEntries(key, entries);
    EXPECT_EQ(status, Status::DB_ERROR);
    status = databaseWrapperObj.Get(key, value);
    EXPECT_EQ(status, Status::DB_ERROR);
    status = databaseWrapperObj.Put(key, value);
    EXPECT_EQ(status, Status::DB_ERROR);
    status = databaseWrapperObj.Delete(key);
    EXPECT_EQ(status, Status::DB_ERROR);
    status = databaseWrapperObj.DeleteKvStore();
    EXPECT_EQ(status, Status::DB_ERROR);
}

/**
 * @tc.name: TestBaseEventIdStorage002
 * @tc.desc: Test BaseEventIdStorage class with mock
 * @tc.type: FUNC
 * @tc.require: SR000H8DA6
 */
HWTEST_F(SecurityGuardUnitTest, TestBaseEventIdStorage002, TestSize.Level1)
{
    DistributedKvDataManager kvDataManager;
    std::shared_ptr<DatabaseManager> dataManager = std::make_shared<DatabaseManager>(kvDataManager);
    std::shared_ptr<Database> database = std::make_shared<Database>(dataManager);
    std::shared_ptr<DatabaseWrapper> databaseWrapper = std::make_shared<DatabaseWrapper>(database);
    std::shared_ptr<DataStorage> storage = std::make_shared<BaseEventIdStorage>(databaseWrapper);
    std::vector<OHOS::DistributedKv::Entry> allEntries;
    std::map<std::string, std::shared_ptr<ICollectInfo>> infos;
    OHOS::DistributedKv::Entry entry1;
    OHOS::DistributedKv::Entry entry2;
    OHOS::DistributedKv::Entry entry3;
    storage->SaveEntries(allEntries, infos);
    entry1.key = OHOS::DistributedKv::Key("key");
    entry1.value = OHOS::DistributedKv::Value("value");
    entry2.key = OHOS::DistributedKv::Key("key");
    entry2.value = OHOS::DistributedKv::Value(
        "[{\"date\":\"1111\",\"eventContent\":\"content\",\"eventId\":1111,\"version\":\"version\"}]");
    entry3.key = OHOS::DistributedKv::Key("0");
    entry3.value = OHOS::DistributedKv::Value(
        "[{\"date\":\"1111\",\"eventContent\":\"content\",\"eventId\":1111,\"version\":\"version\"}]");
    allEntries.emplace_back(entry3);
    allEntries.emplace_back(entry2);
    storage->SaveEntries(allEntries, infos);

    allEntries.clear();
    allEntries.emplace_back(entry1);
    storage->SaveEntries(allEntries, infos);
}

/**
 * @tc.name: TestDataManagerWrapper001
 * @tc.desc: Test DataManagerWrapper class
 * @tc.type: FUNC
 * @tc.require: SR000H8DA0
 */
HWTEST_F(SecurityGuardUnitTest, TestDataManagerWrapper001, TestSize.Level1)
{
    ErrorCode code = DataManagerWrapper::GetInstance().LoadCacheData();
    EXPECT_NE(code, ErrorCode::FAILED);
    EventDataSt eventData = {
        .eventId = 1011009000,
        .version = "0",
        .date = "test date",
        .content = "test content"
    };
    code = DataManagerWrapper::GetInstance().AddCollectInfo(eventData);
    EXPECT_NE(code, ErrorCode::FAILED);
    MockCollectInfo info;
    code = DataManagerWrapper::GetInstance().GetCollectInfoById("TEST KEY", info);
    EXPECT_EQ(code, DB_OPT_ERR);
    std::vector<int64_t> eventIds;
    std::vector<EventDataSt> eventDatas;
    code = DataManagerWrapper::GetInstance().GetEventDataById(eventIds, eventDatas);
    EXPECT_NE(code, ErrorCode::SUCCESS);
    code = DataManagerWrapper::GetInstance().GetCachedEventDataById(eventIds, eventDatas);
    EXPECT_NE(code, ErrorCode::FAILED);
    code = DataManagerWrapper::GetInstance().DeleteKvStore();
    EXPECT_EQ(code, DB_OPT_ERR);
}

/**
 * @tc.name: TestSecurityGuardUtils001
 * @tc.desc: Test SecurityGuardUtils class
 * @tc.type: FUNC
 * @tc.require: SR000H8DA0
 */
HWTEST_F(SecurityGuardUnitTest, TestSecurityGuardUtils001, TestSize.Level1)
{
    std::string str = "adc";
    uint32_t value32;
    bool isSuccess = SecurityGuardUtils::StrToU32(str, value32);
    EXPECT_FALSE(isSuccess);
    int64_t value64;
    isSuccess = SecurityGuardUtils::StrToI64(str, value64);
    EXPECT_FALSE(isSuccess);

    str = "2000000000000000000000000";
    isSuccess = SecurityGuardUtils::StrToU32(str, value32);
    EXPECT_FALSE(isSuccess);
    isSuccess = SecurityGuardUtils::StrToI64(str, value64);
    EXPECT_FALSE(isSuccess);

    str = "123abc";
    isSuccess = SecurityGuardUtils::StrToU32(str, value32);
    EXPECT_FALSE(isSuccess);
    isSuccess = SecurityGuardUtils::StrToI64(str, value64);
    EXPECT_FALSE(isSuccess);
    std::string data = SecurityGuardUtils::GetData();
}

/**
 * @tc.name: TestJsonCfg001
 * @tc.desc: Test Unmarshal with uint64_t
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(SecurityGuardUnitTest, TestJsonCfg001, TestSize.Level1)
{
    uint64_t valueU64 = 0;
    std::vector<int32_t> vectorI32 = {};
    nlohmann::json json;
    json["uint64"] = valueU64;
    json["vector32"] = vectorI32;
    bool isSuccess = JsonCfg::Unmarshal(valueU64, json, "uint64");
    EXPECT_TRUE(isSuccess);
    isSuccess = JsonCfg::Unmarshal(valueU64, json, "fakeKey");
    EXPECT_FALSE(isSuccess);
    isSuccess = JsonCfg::Unmarshal(valueU64, json, "vector32");
    EXPECT_FALSE(isSuccess);
}

/**
 * @tc.name: TestJsonCfg002
 * @tc.desc: Test Unmarshal with int64_t
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(SecurityGuardUnitTest, TestJsonCfg002, TestSize.Level1)
{
    int64_t valueI64 = 0;
    std::vector<int32_t> vectorI32 = {};
    nlohmann::json json;
    json["int64"] = valueI64;
    json["vector32"] = vectorI32;
    bool isSuccess = JsonCfg::Unmarshal(valueI64, json, "int64");
    EXPECT_TRUE(isSuccess);
    isSuccess = JsonCfg::Unmarshal(valueI64, json, "fakeKey");
    EXPECT_FALSE(isSuccess);
    isSuccess = JsonCfg::Unmarshal(valueI64, json, "vector32");
    EXPECT_FALSE(isSuccess);
}

/**
 * @tc.name: TestJsonCfg003
 * @tc.desc: Test Unmarshal with uint32_t
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(SecurityGuardUnitTest, TestJsonCfg003, TestSize.Level1)
{
    uint32_t valueU32 = 0;
    std::vector<int32_t> vectorI32 = {};
    nlohmann::json json;
    json["uint32"] = valueU32;
    json["vector32"] = vectorI32;
    bool isSuccess = JsonCfg::Unmarshal(valueU32, json, "uint32");
    EXPECT_TRUE(isSuccess);
    isSuccess = JsonCfg::Unmarshal(valueU32, json, "fakeKey");
    EXPECT_FALSE(isSuccess);
    isSuccess = JsonCfg::Unmarshal(valueU32, json, "vector32");
    EXPECT_FALSE(isSuccess);
}

/**
 * @tc.name: TestJsonCfg004
 * @tc.desc: Test Unmarshal with int32_t
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(SecurityGuardUnitTest, TestJsonCfg004, TestSize.Level1)
{
    int32_t valueI32 = 0;
    std::vector<int32_t> vectorI32 = {};
    nlohmann::json json;
    json["int32"] = valueI32;
    json["vector32"] = vectorI32;
    bool isSuccess = JsonCfg::Unmarshal(valueI32, json, "int32");
    EXPECT_TRUE(isSuccess);
    isSuccess = JsonCfg::Unmarshal(valueI32, json, "fakeKey");
    EXPECT_FALSE(isSuccess);
    isSuccess = JsonCfg::Unmarshal(valueI32, json, "vector32");
    EXPECT_FALSE(isSuccess);
}

/**
 * @tc.name: TestJsonCfg005
 * @tc.desc: Test Unmarshal with vector<int>
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(SecurityGuardUnitTest, TestJsonCfg005, TestSize.Level1)
{
    std::vector<int32_t> vectorI32 = {0};
    nlohmann::json json;
    json["vector32"] = vectorI32;
    json["int32"] = 0;
    bool isSuccess = JsonCfg::Unmarshal(vectorI32, json, "vector32");
    EXPECT_TRUE(isSuccess);
    isSuccess = JsonCfg::Unmarshal(vectorI32, json, "fakeKey");
    EXPECT_FALSE(isSuccess);
    isSuccess = JsonCfg::Unmarshal(vectorI32, json, "int32");
    EXPECT_FALSE(isSuccess);
    std::vector<std::string> vectorStr = {"test"};
    json["vectorStr"] = vectorStr;
    isSuccess = JsonCfg::Unmarshal(vectorI32, json, "vectorStr");
    EXPECT_FALSE(isSuccess);
}

/**
 * @tc.name: TestJsonCfg006
 * @tc.desc: Test Unmarshal with vector<string>
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(SecurityGuardUnitTest, TestJsonCfg006, TestSize.Level1)
{
    std::vector<std::string> vectorStr = {};
    nlohmann::json json;
    json["vectorStr"] = vectorStr;
    json["int32"] = 0;
    bool isSuccess = JsonCfg::Unmarshal(vectorStr, json, "vectorStr");
    EXPECT_TRUE(isSuccess);
    isSuccess = JsonCfg::Unmarshal(vectorStr, json, "fakeKey");
    EXPECT_FALSE(isSuccess);
    isSuccess = JsonCfg::Unmarshal(vectorStr, json, "int32");
    EXPECT_FALSE(isSuccess);
    vectorStr.emplace_back("test");
    json["vectorStr"] = vectorStr;
    isSuccess = JsonCfg::Unmarshal(vectorStr, json, "vectorStr");
    EXPECT_TRUE(isSuccess);
    std::vector<int32_t> vectorI32 = {0};
    json["vectorI32"] = vectorI32;
    isSuccess = JsonCfg::Unmarshal(vectorStr, json, "vectorI32");
    EXPECT_FALSE(isSuccess);
}

/**
 * @tc.name: TestJsonCfg007
 * @tc.desc: Test Unmarshal with string
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(SecurityGuardUnitTest, TestJsonCfg007, TestSize.Level1)
{
    std::string str;
    nlohmann::json json;
    json["string"] = str;
    json["int32"] = 0;
    bool isSuccess = JsonCfg::Unmarshal(str, json, "string");
    EXPECT_TRUE(isSuccess);
    isSuccess = JsonCfg::Unmarshal(str, json, "fakeKey");
    EXPECT_FALSE(isSuccess);
    isSuccess = JsonCfg::Unmarshal(str, json, "int32");
    EXPECT_FALSE(isSuccess);
}

/**
 * @tc.name: TestJsonCfg008
 * @tc.desc: Test Unmarshal with ModelCfgSt
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(SecurityGuardUnitTest, TestJsonCfg008, TestSize.Level1)
{
    ModelCfgSt modelCfg = {
        .modelId = 0,
        .modelName = "",
        .version = 0,
        .threatList = {},
        .computeModel = ""
    };
    nlohmann::json json;
    json["int32"] = 0;
    json["object"] = modelCfg;
    bool isSuccess = JsonCfg::Unmarshal(modelCfg, json, "object");
    EXPECT_TRUE(isSuccess);
    isSuccess = JsonCfg::Unmarshal(modelCfg, json, "fakeKey");
    EXPECT_FALSE(isSuccess);
    isSuccess = JsonCfg::Unmarshal(modelCfg, json, "int32");
    EXPECT_FALSE(isSuccess);
}

/**
 * @tc.name: TestJsonCfg009
 * @tc.desc: Test Unmarshal with vector
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(SecurityGuardUnitTest, TestJsonCfg009, TestSize.Level1)
{
    ModelCfgSt modelCfg = {
        .modelId = 0,
        .modelName = "",
        .version = 0,
        .threatList = {},
        .computeModel = ""
    };
    std::vector<ModelCfgSt> vec {modelCfg};
    nlohmann::json json;
    json["int32"] = 0;
    json["object"] = modelCfg;
    json["array"] = vec;
    bool isSuccess = JsonCfg::Unmarshal(vec, json, "array");
    EXPECT_TRUE(isSuccess);
    isSuccess = JsonCfg::Unmarshal(vec, json, "fakeKey");
    EXPECT_FALSE(isSuccess);
    isSuccess = JsonCfg::Unmarshal(vec, json, "int32");
    EXPECT_FALSE(isSuccess);
    std::vector<int32_t> vectorI32 = {0};
    json["vectorI32"] = vectorI32;
    isSuccess = JsonCfg::Unmarshal(vec, json, "vectorI32");
    EXPECT_FALSE(isSuccess);
}

/**
 * @tc.name: TestModelCfgMarshalling001
 * @tc.desc: Test Marshalling with ModelCfgSt
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(SecurityGuardUnitTest, TestModelCfgMarshalling001, TestSize.Level1)
{
    ModelCfgSt modelCfg = {
        .modelId = 0,
        .modelName = "",
        .version = 0,
        .threatList = {},
        .computeModel = ""
    };
    nlohmann::json jsonObj(modelCfg);
    ModelCfgSt modelCfg1 = jsonObj.get<ModelCfgSt>();
    EXPECT_EQ(modelCfg1.modelId, modelCfg.modelId);
}

/**
 * @tc.name: TestModelCfgMarshalling002
 * @tc.desc: Test Marshalling with ThreatCfgSt
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(SecurityGuardUnitTest, TestModelCfgMarshalling002, TestSize.Level1)
{
    ThreatCfgSt threatCfg = {
        .threatId = 0,
        .threatName = "",
        .version = 0,
        .eventList = {},
        .computeModel = ""
    };
    nlohmann::json jsonObj(threatCfg);
    ThreatCfgSt threatCfg1 = jsonObj.get<ThreatCfgSt>();
    EXPECT_EQ(threatCfg1.threatId, threatCfg.threatId);
}

/**
 * @tc.name: TestModelCfgMarshalling003
 * @tc.desc: Test Marshalling with EventCfgSt
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(SecurityGuardUnitTest, TestModelCfgMarshalling003, TestSize.Level1)
{
    EventCfgSt eventCfg = {
        .eventId = 0,
        .eventName = "",
        .version = 0,
        .eventType = 0,
        .dataSensitivityLevel = 0,
        .storageRamNums = 0,
        .storageRomNums = 0
    };
    nlohmann::json jsonObj(eventCfg);
    EventCfgSt eventCfg1 = jsonObj.get<EventCfgSt>();
    EXPECT_EQ(eventCfg1.eventId, eventCfg.eventId);
}

/**
 * @tc.name: TestModelCfgMarshalling004
 * @tc.desc: Test Marshalling with DataMgrCfgSt
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(SecurityGuardUnitTest, TestModelCfgMarshalling004, TestSize.Level1)
{
    DataMgrCfgSt dataMgrCfg = {
        .deviceRom = 0,
        .deviceRam = 0,
        .eventMaxRamNum = 0,
        .eventMaxRomNum = 0
    };
    nlohmann::json jsonObj(dataMgrCfg);
    DataMgrCfgSt dataMgrCfg1 = jsonObj.get<DataMgrCfgSt>();
    EXPECT_EQ(dataMgrCfg1.eventMaxRamNum, dataMgrCfg.eventMaxRamNum);
}

/**
 * @tc.name: TestModelCfgMarshalling005
 * @tc.desc: Test Marshalling with EventDataSt
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(SecurityGuardUnitTest, TestModelCfgMarshalling005, TestSize.Level1)
{
    EventDataSt eventDataSt = {
        .eventId = 0,
        .version = "",
        .date = "",
        .content = ""
    };
    nlohmann::json jsonObj(eventDataSt);
    EventDataSt eventDataSt1 = jsonObj.get<EventDataSt>();
    EXPECT_EQ(eventDataSt1.eventId, eventDataSt.eventId);
}

/**
 * @tc.name: TestModelCfgMarshalling006
 * @tc.desc: Test Marshalling with EventContentSt
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(SecurityGuardUnitTest, TestModelCfgMarshalling006, TestSize.Level1)
{
    EventContentSt eventContentSt = {
        .status = 0,
        .cred = 0,
        .extra = ""
    };
    nlohmann::json jsonObj(eventContentSt);
    EventContentSt eventContentSt1  = jsonObj.get<EventContentSt>();
    EXPECT_EQ(eventContentSt1.cred, eventContentSt.cred);
}

/**
 * @tc.name: TestDataCollectManagerService001
 * @tc.desc: Test OnRemoteRequest with wrong descriptor
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestDataCollectManagerService001, TestSize.Level1)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    int32_t code = service.OnRemoteRequest(DataCollectManagerStub::CMD_DATA_COLLECT, data, reply, option);
    EXPECT_NE(code, ErrorCode::SUCCESS);
}

/**
 * @tc.name: TestDataCollectManagerService002
 * @tc.desc: Test OnRemoteRequest with wrong cmd
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestDataCollectManagerService002, TestSize.Level1)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    bool isSuccess = data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    EXPECT_TRUE(isSuccess);
    int32_t code = service.OnRemoteRequest(0, data, reply, option);
    EXPECT_NE(code, ErrorCode::SUCCESS);
}

/**
 * @tc.name: TestDataCollectManagerService003
 * @tc.desc: Test OnRemoteRequest with empty data
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestDataCollectManagerService003, TestSize.Level1)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    bool isSuccess = data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    EXPECT_TRUE(isSuccess);
    int32_t code = service.OnRemoteRequest(DataCollectManagerStub::CMD_DATA_COLLECT, data, reply, option);
    EXPECT_EQ(code, ErrorCode::BAD_PARAM);
}

/**
 * @tc.name: TestDataCollectManagerService004
 * @tc.desc: Test OnRemoteRequest with empty data
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestDataCollectManagerService004, TestSize.Level1)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    bool isSuccess = data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    EXPECT_TRUE(isSuccess);
    int32_t code = service.OnRemoteRequest(DataCollectManagerStub::CMD_DATA_REQUEST, data, reply, option);
    EXPECT_EQ(code, ErrorCode::BAD_PARAM);
}

/**
 * @tc.name: TestDataCollectManagerService005
 * @tc.desc: Test OnRemoteRequest with wrong data
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestDataCollectManagerService005, TestSize.Level1)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    bool isSuccess = data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    EXPECT_TRUE(isSuccess);
    isSuccess = data.WriteInt64(0);
    EXPECT_TRUE(isSuccess);
    isSuccess = data.WriteString("");
    EXPECT_TRUE(isSuccess);
    isSuccess = data.WriteString("");
    EXPECT_TRUE(isSuccess);
    int32_t code = service.OnRemoteRequest(DataCollectManagerStub::CMD_DATA_COLLECT, data, reply, option);
    EXPECT_EQ(code, ErrorCode::NO_PERMISSION);
}

/**
 * @tc.name: TestDataCollectManagerService006
 * @tc.desc: Test OnRemoteRequest with null object
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestDataCollectManagerService006, TestSize.Level1)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    bool isSuccess = data.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    EXPECT_TRUE(isSuccess);
    isSuccess = data.WriteString("devId");
    EXPECT_TRUE(isSuccess);
    isSuccess = data.WriteString("eventList");
    EXPECT_TRUE(isSuccess);
    isSuccess = data.WriteRemoteObject(nullptr);
    EXPECT_FALSE(isSuccess);
    int32_t code = service.OnRemoteRequest(DataCollectManagerStub::CMD_DATA_REQUEST, data, reply, option);
    EXPECT_EQ(code, ErrorCode::BAD_PARAM);
}

/**
 * @tc.name: TestDataCollectManagerService007
 * @tc.desc: Test Dump with bad param
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestDataCollectManagerService007, TestSize.Level1)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::vector<std::u16string> args;
    int ret = service.Dump(-1, args);
    EXPECT_EQ(ret, BAD_PARAM);
}

/**
 * @tc.name: TestDataCollectManagerService008
 * @tc.desc: Test Dump with right param
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestDataCollectManagerService008, TestSize.Level1)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::vector<std::u16string> args;
    int ret = service.Dump(0, args);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestDataCollectManagerService009
 * @tc.desc: Test Dump with right param
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestDataCollectManagerService009, TestSize.Level1)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::string arg = "-h";
    std::vector<std::u16string> args;
    args.emplace_back(Str8ToStr16(arg));
    int ret = service.Dump(0, args);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestDataCollectManagerService010
 * @tc.desc: Test Dump with bad param
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestDataCollectManagerService010, TestSize.Level1)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::string arg = "-i";
    std::vector<std::u16string> args;
    args.emplace_back(Str8ToStr16(arg));
    int ret = service.Dump(0, args);
    EXPECT_EQ(ret, BAD_PARAM);
}

/**
 * @tc.name: TestDataCollectManagerService011
 * @tc.desc: Test Dump with bad param
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestDataCollectManagerService011, TestSize.Level1)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::string arg = "-i";
    std::vector<std::u16string> args;
    args.emplace_back(Str8ToStr16(arg));
    args.emplace_back(Str8ToStr16(arg));
    int ret = service.Dump(0, args);
    EXPECT_EQ(ret, BAD_PARAM);
}

/**
 * @tc.name: TestDataCollectManagerService012
 * @tc.desc: Test Dump with right param
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestDataCollectManagerService012, TestSize.Level1)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::string arg = "-i";
    std::vector<std::u16string> args;
    args.emplace_back(Str8ToStr16(arg));
    arg = "0";
    args.emplace_back(Str8ToStr16(arg));
    int ret = service.Dump(0, args);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestRiskAnalysisManagerService002
 * @tc.desc: Test OnRemoteRequest with wrong descriptor
 * @tc.type: FUNC
 * @tc.require: SR000H8DA0
 */
HWTEST_F(SecurityGuardUnitTest, TestRiskAnalysisManagerService001, TestSize.Level1)
{
    RiskAnalysisManagerService service(RISK_ANALYSIS_MANAGER_SA_ID, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    int32_t code = service.OnRemoteRequest(RiskAnalysisManagerStub::CMD_GET_SECURITY_MODEL_RESULT, data, reply, option);
    EXPECT_NE(code, ErrorCode::SUCCESS);
}

/**
 * @tc.name: TestRiskAnalysisManagerService002
 * @tc.desc: Test OnRemoteRequest with wrong cmd
 * @tc.type: FUNC
 * @tc.require: SR000H8DA0
 */
HWTEST_F(SecurityGuardUnitTest, TestRiskAnalysisManagerService002, TestSize.Level1)
{
    RiskAnalysisManagerService service(RISK_ANALYSIS_MANAGER_SA_ID, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    bool isSuccess = data.WriteInterfaceToken(IRiskAnalysisManager::GetDescriptor());
    EXPECT_TRUE(isSuccess);
    int32_t code = service.OnRemoteRequest(0, data, reply, option);
    EXPECT_NE(code, ErrorCode::SUCCESS);
}

/**
 * @tc.name: TestRiskAnalysisManagerService003
 * @tc.desc: Test OnRemoteRequest with null data content
 * @tc.type: FUNC
 * @tc.require: SR000H8DA0
 */
HWTEST_F(SecurityGuardUnitTest, TestRiskAnalysisManagerService003, TestSize.Level1)
{
    RiskAnalysisManagerService service(RISK_ANALYSIS_MANAGER_SA_ID, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    bool isSuccess = data.WriteInterfaceToken(IRiskAnalysisManager::GetDescriptor());
    EXPECT_TRUE(isSuccess);
    int32_t code = service.OnRemoteRequest(RiskAnalysisManagerStub::CMD_GET_SECURITY_MODEL_RESULT, data, reply, option);
    EXPECT_EQ(code, ErrorCode::BAD_PARAM);
}

/**
 * @tc.name: TestRiskAnalysisManagerService004
 * @tc.desc: Test OnRemoteRequest with null object
 * @tc.type: FUNC
 * @tc.require: SR000H8DA0
 */
HWTEST_F(SecurityGuardUnitTest, TestRiskAnalysisManagerService004, TestSize.Level1)
{
    RiskAnalysisManagerService service(RISK_ANALYSIS_MANAGER_SA_ID, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    bool isSuccess = data.WriteInterfaceToken(IRiskAnalysisManager::GetDescriptor());
    EXPECT_TRUE(isSuccess);
    isSuccess = data.WriteString("");
    EXPECT_TRUE(isSuccess);
    isSuccess = data.WriteUint32(0);
    EXPECT_TRUE(isSuccess);
    isSuccess = data.WriteRemoteObject(nullptr);
    EXPECT_FALSE(isSuccess);
    int32_t code = service.OnRemoteRequest(RiskAnalysisManagerStub::CMD_GET_SECURITY_MODEL_RESULT, data, reply, option);
    EXPECT_EQ(code, ErrorCode::BAD_PARAM);
}

/**
 * @tc.name: TestModelManager001
 * @tc.desc: Test AnalyseRisk with eventId
 * @tc.type: FUNC
 * @tc.require: SR000H8DA0
 */
HWTEST_F(SecurityGuardUnitTest, TestModelManager001, TestSize.Level1)
{
    std::vector<int64_t> events;
    std::string eventInfo;
    ErrorCode code = ModelManager::GetInstance().AnalyseRisk(events, eventInfo);
    EXPECT_EQ(code, ErrorCode::SUCCESS);

    events.emplace_back(1011009000);
    code = ModelManager::GetInstance().AnalyseRisk(events, eventInfo);
    EXPECT_NE(code, ErrorCode::FAILED);
}

/**
 * @tc.name: TestRiskAnalysisModel001
 * @tc.desc: Test RiskAnalysis with empty eventData
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(SecurityGuardUnitTest, TestRiskAnalysisModel001, TestSize.Level1)
{
    std::vector<EventDataSt> eventData;
    std::string eventInfo;
    ErrorCode code = RiskAnalysisModel::RiskAnalysis(eventData, eventInfo);
    EXPECT_EQ(code, ErrorCode::SUCCESS);
}

/**
 * @tc.name: TestRiskAnalysisModel002
 * @tc.desc: Test RiskAnalysis with empty content
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(SecurityGuardUnitTest, TestRiskAnalysisModel002, TestSize.Level1)
{
    std::vector<EventDataSt> eventData;
    EventDataSt event;
    eventData.emplace_back(event);
    std::string eventInfo;
    ErrorCode code = RiskAnalysisModel::RiskAnalysis(eventData, eventInfo);
    EXPECT_NE(code, ErrorCode::SUCCESS);
}

/**
 * @tc.name: TestRiskAnalysisModel003
 * @tc.desc: Test RiskAnalysis with right content
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(SecurityGuardUnitTest, TestRiskAnalysisModel003, TestSize.Level1)
{
    std::vector<EventDataSt> eventData;
    EventDataSt event;
    event.content = "{\"cred\":0,\"extra\":\"\",\"status\":0}";
    eventData.emplace_back(event);
    std::string eventInfo;
    ErrorCode code = RiskAnalysisModel::RiskAnalysis(eventData, eventInfo);
    EXPECT_EQ(code, ErrorCode::SUCCESS);
}

/**
 * @tc.name: TestRiskAnalysisModel004
 * @tc.desc: Test RiskAnalysis with right content
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(SecurityGuardUnitTest, TestRiskAnalysisModel004, TestSize.Level1)
{
    std::vector<EventDataSt> eventData;
    EventDataSt event;
    event.content = "{\"cred\":1,\"extra\":\"\",\"status\":0}";
    eventData.emplace_back(event);
    std::string eventInfo;
    ErrorCode code = RiskAnalysisModel::RiskAnalysis(eventData, eventInfo);
    EXPECT_NE(code, ErrorCode::SUCCESS);
}

/**
 * @tc.name: TestRiskAnalysisModel005
 * @tc.desc: Test RiskAnalysis with right content
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(SecurityGuardUnitTest, TestRiskAnalysisModel005, TestSize.Level1)
{
    std::vector<EventDataSt> eventData;
    EventDataSt event;
    event.content = "{\"cred\":1,\"extra\":\"\",\"status\":1}";
    eventData.emplace_back(event);
    std::string eventInfo;
    ErrorCode code = RiskAnalysisModel::RiskAnalysis(eventData, eventInfo);
    EXPECT_EQ(code, ErrorCode::SUCCESS);
}

/**
 * @tc.name: TestUeventListener001
 * @tc.desc: Test Start with mock
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(SecurityGuardUnitTest, TestUeventListener001, TestSize.Level1)
{
    KernelInterfaceAdapter adapter;
    MockUeventListenerImpl mockObj(adapter);
    EXPECT_CALL(mockObj, InitUevent).Times(AtLeast(1)).WillRepeatedly(Return(false));
    UeventListener listener(mockObj);
    listener.Start();
}

/**
 * @tc.name: TestUeventListener002
 * @tc.desc: Test InitUevent with mock
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(SecurityGuardUnitTest, TestUeventListener002, TestSize.Level1)
{
    MockKernelInterfaceAdapter mockObj;
    UeventListenerImpl impl(mockObj);
    EXPECT_CALL(mockObj, Socket).Times(AtLeast(1)).WillOnce(Return(-1)).WillRepeatedly(Return(0));
    EXPECT_CALL(mockObj, Bind).Times(AtLeast(1)).WillOnce(Return(-1)).WillRepeatedly(Return(0));
    bool isSuccess = impl.InitUevent();
    EXPECT_FALSE(isSuccess);
    isSuccess = impl.InitUevent();
    EXPECT_FALSE(isSuccess);
    isSuccess = impl.InitUevent();
    EXPECT_FALSE(isSuccess);
    isSuccess = impl.InitUevent();
    EXPECT_FALSE(isSuccess);
}

/**
 * @tc.name: TestUeventListener003
 * @tc.desc: Test UeventListen with mock
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(SecurityGuardUnitTest, TestUeventListener003, TestSize.Level1)
{
    MockKernelInterfaceAdapter mockObj;
    UeventListenerImpl impl(mockObj);
    char buffer[1024] = { 0 };
    EXPECT_CALL(mockObj, Poll).Times(AtLeast(1)).WillOnce(Return(0)).WillOnce(
        [] (struct pollfd* const fds, nfds_t fdCount, int timeout) -> int {
            fds->revents = -1;
            return 1;
        }).WillOnce(
            [] (struct pollfd* const fds, nfds_t fdCount, int timeout) -> int {
                fds->revents = 0;
                return 1;
            }).WillRepeatedly(
                [] (struct pollfd* const fds, nfds_t fdCount, int timeout) -> int {
                    fds->revents = 1;
                    return 1;
                });
    EXPECT_CALL(mockObj, Recv).Times(AtLeast(1)).WillOnce(Return(0)).WillRepeatedly(Return(1));
    int32_t count = impl.UeventListen(nullptr, 0);
    EXPECT_EQ(count, 0);
    count = impl.UeventListen(buffer, sizeof(buffer));
    EXPECT_EQ(count, 0);
    count = impl.UeventListen(buffer, sizeof(buffer) - 1);
    EXPECT_EQ(count, 1);
}

/**
 * @tc.name: TestUeventListener004
 * @tc.desc: Test ParseEvent with different content
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(SecurityGuardUnitTest, TestUeventListener004, TestSize.Level1)
{
    KernelInterfaceAdapter obj;
    UeventListenerImpl impl(obj);
    char buffer[1024] = { 0 };
    impl.ParseEvent(nullptr, 0);
    impl.ParseEvent(buffer, sizeof(buffer) + 1);
    impl.ParseEvent(buffer, sizeof(buffer) - 1);
    const char* content = "SG_KERNEL_COLLECT_DATA_CMD=1-0-34-{\"status\":1, \"cred\":1,\"extra\":\"\"}";
    (void) memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
    errno_t rc = memcpy_s(buffer, sizeof(buffer), content, strlen(content));
    EXPECT_TRUE(rc == EOK);
    impl.ParseEvent(buffer, strlen(content));

    const char* content1 = "SG_KERNEL_COLLECT_DATA_CMD=1-0-38-{\"status\":\"1\", \"cred\":\"1\",\"extra\":\"\"}";
    (void) memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
    rc = memcpy_s(buffer, sizeof(buffer), content1, strlen(content1));
    EXPECT_TRUE(rc == EOK);
    impl.ParseEvent(buffer, strlen(content1));

    const char* content2 = "SG_KERNEL_COLLECT_DATA_CMD=1-0-39-{\"status\":\"1\", \"cred\":\"1\",\"extra\":\"\"}";
    (void) memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
    rc = memcpy_s(buffer, sizeof(buffer), content2, strlen(content2));
    EXPECT_TRUE(rc == EOK);
    impl.ParseEvent(buffer, strlen(content2));

    const char* content3 = "SG_KERNEL_COLLECT_DATA_CMD=1-0-34-{\"status\":1, \"cred\":1,\"extra\":\"\"}-0";
    (void) memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
    rc = memcpy_s(buffer, sizeof(buffer), content3, strlen(content3));
    EXPECT_TRUE(rc == EOK);
    impl.ParseEvent(buffer, strlen(content3));
}

/**
 * @tc.name: TestUeventNotify001
 * @tc.desc: Test NotifyScan with mock
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestUeventNotify001, TestSize.Level1)
{
    MockKernelInterfaceAdapter mockObj;
    UeventNotify notify(mockObj);
    EXPECT_CALL(mockObj, Open).Times(AtLeast(1)).WillOnce(Return(-1)).WillRepeatedly(Return(0));
    EXPECT_CALL(mockObj, Write).Times(AtLeast(1)).WillOnce(Return(0)).WillRepeatedly(Return(1));
    notify.NotifyScan();
    notify.NotifyScan();
    notify.NotifyScan();
}

/**
 * @tc.name: TestUeventNotify002
 * @tc.desc: Test AddWhiteList with mock
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestUeventNotify002, TestSize.Level1)
{
    std::vector<int64_t> whitelist;
    MockKernelInterfaceAdapter mockObj;
    UeventNotify notify(mockObj);
    EXPECT_CALL(mockObj, Open).Times(AtLeast(1)).WillOnce(Return(-1)).WillRepeatedly(Return(0));
    EXPECT_CALL(mockObj, Write).Times(AtLeast(1)).WillOnce(Return(0)).WillRepeatedly(Return(5));
    notify.AddWhiteList(whitelist);
    whitelist.emplace_back(0);
    notify.AddWhiteList(whitelist);
    notify.AddWhiteList(whitelist);
    notify.AddWhiteList(whitelist);
}

/**
 * @tc.name: TestKernelInterfaceAdapter001
 * @tc.desc: Test KernelInterfaceAdapter bind interface
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestKernelInterfaceAdapter001, TestSize.Level1)
{
    KernelInterfaceAdapter adapter;
    struct sockaddr_nl addr = {};
    int ret = adapter.Bind(0, reinterpret_cast<const struct sockaddr *>(&addr), sizeof(addr));
    EXPECT_FALSE(ret == 0);
    ret = adapter.Bind(0, nullptr, 0);
    EXPECT_TRUE(ret == -1);
}

/**
 * @tc.name: TestKernelInterfaceAdapter002
 * @tc.desc: Test KernelInterfaceAdapter poll interface
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestKernelInterfaceAdapter002, TestSize.Level1)
{
    KernelInterfaceAdapter adapter;
    struct pollfd fds = {};
    int ret = adapter.Poll(&fds, 1, -1);
    EXPECT_FALSE(ret == 0);
    ret = adapter.Poll(nullptr, 0, -1);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: TestKernelInterfaceAdapter003
 * @tc.desc: Test KernelInterfaceAdapter recv interface
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestKernelInterfaceAdapter003, TestSize.Level1)
{
    KernelInterfaceAdapter adapter;
    char buffer[1] = {};
    int ret = adapter.Recv(0, buffer, sizeof(buffer), 0);
    EXPECT_FALSE(ret == 0);
    ret = adapter.Recv(0, nullptr, 0, 0);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: TestKernelInterfaceAdapter004
 * @tc.desc: Test KernelInterfaceAdapter open interface
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestKernelInterfaceAdapter004, TestSize.Level1)
{
    KernelInterfaceAdapter adapter;
    int ret = adapter.Open("/proc/kernel_sg", 0);
    EXPECT_TRUE(ret == 0);
    ret = adapter.Open("test", 0);
    EXPECT_TRUE(ret == -1);
}

/**
 * @tc.name: TestKernelInterfaceAdapter005
 * @tc.desc: Test KernelInterfaceAdapter write interface
 * @tc.type: FUNC
 * @tc.require: SR000H9A70
 */
HWTEST_F(SecurityGuardUnitTest, TestKernelInterfaceAdapter005, TestSize.Level1)
{
    KernelInterfaceAdapter adapter;
    char buffer[1] = {};
    int ret = adapter.Write(0, buffer, sizeof(buffer));
    EXPECT_FALSE(ret == 0);
    ret = adapter.Write(0, nullptr, 0);
    EXPECT_TRUE(ret == 0);
}
}