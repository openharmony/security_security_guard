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

#include "security_guard_config_manager_test.h"

#include "file_ex.h"
#include "gmock/gmock.h"
#include "nlohmann/json.hpp"
#include <thread>
#include <fstream>
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "security_event_info.h"
#include "json_cfg.h"
#define private public
#define protected public
#include "base_config.h"
#include "config_data_manager.h"
#include "i_model_info.h"
#include "config_define.h"
#include "config_manager.h"
#include "config_operator.h"
#include "config_subscriber.h"
#include "event_config.h"
#include "model_cfg_marshalling.h"
#include "model_config.h"
#include "rdb_helper.h"
#include "security_guard_log.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityGuardTest;
namespace OHOS {
    std::shared_ptr<NativeRdb::MockRdbHelperInterface> NativeRdb::RdbHelper::instance_ = nullptr;
    std::mutex NativeRdb::RdbHelper::mutex_ {};
}
namespace OHOS::Security::SecurityGuardTest {

void SecurityGuardConfigManagerTest::SetUpTestCase()
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
}

void SecurityGuardConfigManagerTest::TearDownTestCase()
{
}

void SecurityGuardConfigManagerTest::SetUp()
{
}

void SecurityGuardConfigManagerTest::TearDown()
{
}

class MockBaseConfig : public BaseConfig {
public:
    MockBaseConfig() = default;
    ~MockBaseConfig() override = default;
    MOCK_METHOD0(Check, bool());
    MOCK_METHOD1(Load, bool(int));
    MOCK_METHOD0(Parse, bool());
    MOCK_METHOD0(Update, bool());
};

class TestBaseConfig : public BaseConfig {
public:
    TestBaseConfig() = default;
    ~TestBaseConfig() override = default;
    MOCK_METHOD1(Load, bool(int));
    MOCK_METHOD0(Parse, bool());
    MOCK_METHOD0(Update, bool());
};

HWTEST_F(SecurityGuardConfigManagerTest, TestConfigOperator001, TestSize.Level1)
{
    MockBaseConfig config;
    auto configOptor = std::make_unique<ConfigOperator>(config);
    EXPECT_CALL(config, Load).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(config, Check).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(config, Parse).WillOnce(Return(false)).WillRepeatedly(Return(true));
    bool success = configOptor->Init();
    EXPECT_FALSE(success);
    success = configOptor->Init();
    EXPECT_FALSE(success);
    success = configOptor->Init();
    EXPECT_FALSE(success);
    success = configOptor->Init();
    EXPECT_TRUE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestConfigOperator002, TestSize.Level1)
{
    MockBaseConfig config;
    auto configOptor = std::make_unique<ConfigOperator>(config);
    EXPECT_CALL(config, Load).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(config, Check).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(config, Update).WillOnce(Return(false)).WillRepeatedly(Return(true));
    bool success = configOptor->Update();
    EXPECT_FALSE(success);
    success = configOptor->Update();
    EXPECT_FALSE(success);
    success = configOptor->Update();
    EXPECT_FALSE(success);
    success = configOptor->Update();
    EXPECT_TRUE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestBaseConfig001, TestSize.Level1)
{
    TestBaseConfig config;
    config.stream_.close();
    bool success = config.Check();
    EXPECT_FALSE(success);
    config.stream_.open("test.txt");
    success = config.Check();
    EXPECT_FALSE(success);
    config.stream_.open("/data/test/unittest/resource/stream_empty.txt");
    success = config.Check();
    EXPECT_FALSE(success);
    config.stream_.open("/data/test/unittest/resource/stream_not_empty.txt");
    success = config.Check();
    EXPECT_TRUE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestConfigDataManager001, TestSize.Level1)
{
    EventCfg config = {};
    std::string eventName = "test eventName";
    config.eventName = eventName;
    ConfigDataManager::GetInstance().InsertEventMap(config.eventId, config);
    EventCfg outConfig = {};
    bool success = ConfigDataManager::GetInstance().GetEventConfig(config.eventId, outConfig);
    EXPECT_TRUE(success);
    EXPECT_TRUE(outConfig.eventName == config.eventName);
    std::vector<int64_t> eventIds = ConfigDataManager::GetInstance().GetAllEventIds();
    EXPECT_TRUE(eventIds.size() == 1);
    EXPECT_TRUE(eventIds[0] == 0);
    ConfigDataManager::GetInstance().ResetEventMap();
    success = ConfigDataManager::GetInstance().GetEventConfig(config.eventId, outConfig);
    EXPECT_FALSE(success);
    eventIds = ConfigDataManager::GetInstance().GetAllEventIds();
    EXPECT_TRUE(eventIds.size() == 0);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestConfigDataManager002, TestSize.Level1)
{
    ModelCfg config = {};
    std::string path = "test path";
    config.path = path;
    ConfigDataManager::GetInstance().InsertModelMap(config.modelId, config);
    ModelCfg outConfig = {};
    bool success = ConfigDataManager::GetInstance().GetModelConfig(config.modelId, outConfig);
    EXPECT_TRUE(success);
    EXPECT_TRUE(outConfig.path == config.path);
    ConfigDataManager::GetInstance().ResetModelMap();
    success = ConfigDataManager::GetInstance().GetModelConfig(config.modelId, outConfig);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestConfigDataManager003, TestSize.Level1)
{
    std::set<int64_t> eventIds {1};
    int32_t modelId = 0;
    ConfigDataManager::GetInstance().InsertModelToEventMap(modelId, eventIds);
    std::vector<int64_t> outEventIds = ConfigDataManager::GetInstance().GetEventIds(modelId);
    EXPECT_TRUE(outEventIds.size() == 1);
    EXPECT_TRUE(outEventIds[0] == 1);
    ConfigDataManager::GetInstance().ResetModelToEventMap();
    outEventIds = ConfigDataManager::GetInstance().GetEventIds(modelId);
    EXPECT_TRUE(outEventIds.size() == 0);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestEventConfig002, TestSize.Level1)
{
    ConfigDataManager::GetInstance().ResetEventMap();
    ConfigDataManager::GetInstance().ResetModelMap();
    ConfigDataManager::GetInstance().ResetModelToEventMap();
    EventConfig config;
    bool success = config.Parse();
    EXPECT_FALSE(success);
    config.stream_.open("/data/test/unittest/resource/security_guard_preset_event.cfg");
    success = config.Parse();
    EXPECT_TRUE(success);
    EventCfg eventCfg;
    eventCfg.eventId = 2;
    success = ConfigDataManager::GetInstance().GetEventConfig(eventCfg.eventId, eventCfg);
    EXPECT_TRUE(success);
    EXPECT_TRUE(eventCfg.eventName == "preset_event");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestEventConfig003, TestSize.Level1)
{
    ConfigDataManager::GetInstance().ResetEventMap();
    ConfigDataManager::GetInstance().ResetModelMap();
    ConfigDataManager::GetInstance().ResetModelToEventMap();
    EventConfig config;
    bool success = config.Parse();
    EXPECT_FALSE(success);
    config.stream_.open("/data/test/unittest/resource/security_guard_update_event.cfg");
    EXPECT_TRUE(config.stream_.is_open());
    success = config.Parse();
    EXPECT_TRUE(success);
    EventCfg eventCfg;
    eventCfg.eventId = 3;
    success = ConfigDataManager::GetInstance().GetEventConfig(eventCfg.eventId, eventCfg);
    EXPECT_TRUE(success);
    EXPECT_TRUE(eventCfg.eventName == "update_event");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestEventConfig001, TestSize.Level1)
{
    EventConfig config;
    bool success = config.Load(INIT_MODE);
    EXPECT_TRUE(success);
    EXPECT_TRUE(config.Load(UPDATE_MODE));
    config.Update();
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelConfig001, TestSize.Level1)
{
    ModelConfig config;
    bool success = config.Load(INIT_MODE);
    EXPECT_TRUE(success);
    EXPECT_TRUE(config.Load(UPDATE_MODE));
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelConfig002, TestSize.Level1)
{
    ConfigDataManager::GetInstance().ResetEventMap();
    ConfigDataManager::GetInstance().ResetModelMap();
    ConfigDataManager::GetInstance().ResetModelToEventMap();
    ModelConfig config;
    bool success = config.Parse();
    EXPECT_FALSE(success);
    config.stream_.open("/data/test/unittest/resource/security_guard_preset_model.cfg");
    EXPECT_TRUE(config.stream_.is_open());
    success = config.Parse();
    EXPECT_TRUE(success);
    ModelCfg modelCfg;
    modelCfg.modelId = 2;
    success = ConfigDataManager::GetInstance().GetModelConfig(modelCfg.modelId, modelCfg);
    EXPECT_TRUE(success);
    EXPECT_TRUE(modelCfg.path == "preset_model");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelConfig003, TestSize.Level1)
{
    ConfigDataManager::GetInstance().ResetEventMap();
    ConfigDataManager::GetInstance().ResetModelMap();
    ConfigDataManager::GetInstance().ResetModelToEventMap();
    ModelConfig config;
    bool success = config.Parse();
    EXPECT_FALSE(success);
    config.stream_.open("/data/test/unittest/resource/security_guard_update_model.cfg");
    EXPECT_TRUE(config.stream_.is_open());
    success = config.Parse();
    EXPECT_TRUE(success);
    ModelCfg modelCfg;
    modelCfg.modelId = 3;
    success = ConfigDataManager::GetInstance().GetModelConfig(modelCfg.modelId, modelCfg);
    EXPECT_TRUE(success);
    EXPECT_TRUE(modelCfg.path == "update_model");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelConfig004, TestSize.Level1)
{
    ConfigDataManager::GetInstance().ResetEventMap();
    ConfigDataManager::GetInstance().ResetModelMap();
    ConfigDataManager::GetInstance().ResetModelToEventMap();
    ModelConfig config;
    nlohmann::json jsonObj;
    ModelCfg modelCfg;
    to_json(jsonObj, modelCfg);
    DataMgrCfgSt dataMgrCfg{};
    to_json(jsonObj, dataMgrCfg);
    from_json(jsonObj, dataMgrCfg);
    SecEvent eventDataSt{};
    to_json(jsonObj, eventDataSt);
    EventContentSt eventContentSt{};
    to_json(jsonObj, eventContentSt);
    from_json(jsonObj, eventContentSt);
    EventCfg eventCfg{};
    jsonObj["modelId"] = "xxx";
    from_json(jsonObj, modelCfg);
    jsonObj["eventId"] = "xxx";
    from_json(jsonObj, eventCfg);
    bool success = config.Parse();
    EXPECT_FALSE(success);
    config.stream_.open("/data/test/unittest/resource/security_guard_preset_model.cfg");
    EXPECT_TRUE(config.stream_.is_open());
    EXPECT_TRUE(config.Update());
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelConfig005, TestSize.Level1)
{
    ConfigDataManager::GetInstance().ResetEventMap();
    ConfigDataManager::GetInstance().ResetModelMap();
    ConfigDataManager::GetInstance().ResetModelToEventMap();
    ConfigDataManager::GetInstance().GetAllModelIds();
    ConfigDataManager::GetInstance().ResetEventToTableMap();
    EXPECT_TRUE(ConfigDataManager::GetInstance().GetTableFromEventId(0).empty());
    EXPECT_TRUE(ConfigDataManager::GetInstance().GetAllEventConfigs().empty());
}

HWTEST_F(SecurityGuardConfigManagerTest, TestConfigSubsciber003, TestSize.Level1)
{
    EXPECT_TRUE(
        ConfigSubscriber::UpdateConfig(CONFIG_CACHE_FILES[EVENT_CFG_INDEX]));
    EXPECT_TRUE(
        ConfigSubscriber::UpdateConfig(CONFIG_CACHE_FILES[MODEL_CFG_INDEX]));
    EXPECT_TRUE(ConfigSubscriber::UpdateConfig("/data/service/el1/public/security_guard/tmp/signature_rule.json"));
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling001, TestSize.Level1)
{
    nlohmann::json jsonObj;
    SecurityGuard::AppDetectionCfg cfg = jsonObj.get<SecurityGuard::AppDetectionCfg>();
    EXPECT_TRUE(cfg.detectionCategory == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling002, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["detectionCategory"] = 0;
    SecurityGuard::AppDetectionCfg cfg = jsonObj.get<SecurityGuard::AppDetectionCfg>();
    EXPECT_TRUE(cfg.detectionCategory == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling003, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["detectionCategory"] = "detectionCategory";
    SecurityGuard::AppDetectionCfg cfg = jsonObj.get<SecurityGuard::AppDetectionCfg>();
    EXPECT_TRUE(cfg.detectionCategory == "detectionCategory");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling004, TestSize.Level1)
{
    nlohmann::json jsonObj;
    SecurityGuard::Field field = jsonObj.get<SecurityGuard::Field>();
    EXPECT_TRUE(field.fieldName == "");
    EXPECT_TRUE(field.fieldType == "");
    EXPECT_TRUE(field.value == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling005, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["fieldName"] = 0;
    SecurityGuard::Field field = jsonObj.get<SecurityGuard::Field>();
    EXPECT_TRUE(field.fieldName == "");
    EXPECT_TRUE(field.fieldType == "");
    EXPECT_TRUE(field.value == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling006, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["fieldName"] = 0;
    jsonObj["fieldType"] = 0;
    SecurityGuard::Field field = jsonObj.get<SecurityGuard::Field>();
    EXPECT_TRUE(field.fieldName == "");
    EXPECT_TRUE(field.fieldType == "");
    EXPECT_TRUE(field.value == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling007, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["fieldName"] = 0;
    jsonObj["fieldType"] = 0;
    jsonObj["value"] = 0;
    SecurityGuard::Field field = jsonObj.get<SecurityGuard::Field>();
    EXPECT_TRUE(field.fieldName == "");
    EXPECT_TRUE(field.fieldType == "");
    EXPECT_TRUE(field.value == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling008, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["fieldName"] = "fieldName";
    jsonObj["fieldType"] = 0;
    jsonObj["value"] = 0;
    SecurityGuard::Field field = jsonObj.get<SecurityGuard::Field>();
    EXPECT_TRUE(field.fieldName == "");
    EXPECT_TRUE(field.fieldType == "");
    EXPECT_TRUE(field.value == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling009, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["fieldName"] = "fieldName";
    jsonObj["fieldType"] = "fieldType";
    jsonObj["value"] = 0;
    SecurityGuard::Field field = jsonObj.get<SecurityGuard::Field>();
    EXPECT_TRUE(field.fieldName == "");
    EXPECT_TRUE(field.fieldType == "");
    EXPECT_TRUE(field.value == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling010, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["fieldName"] = "fieldName";
    jsonObj["fieldType"] = "fieldType";
    jsonObj["value"] = "value";
    SecurityGuard::Field field = jsonObj.get<SecurityGuard::Field>();
    EXPECT_TRUE(field.fieldName == "fieldName");
    EXPECT_TRUE(field.fieldType == "fieldType");
    EXPECT_TRUE(field.value == "value");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling011, TestSize.Level1)
{
    nlohmann::json jsonObj;
    SecurityGuard::Rule rule = jsonObj.get<SecurityGuard::Rule>();
    EXPECT_TRUE(rule.eventId == 0);
    EXPECT_TRUE(rule.fields.empty());
    EXPECT_TRUE(rule.fieldsRelation == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling012, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["eventId"] = "";
    SecurityGuard::Rule rule = jsonObj.get<SecurityGuard::Rule>();
    EXPECT_TRUE(rule.eventId == 0);
    EXPECT_TRUE(rule.fields.empty());
    EXPECT_TRUE(rule.fieldsRelation == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling013, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["eventId"] = "";
    jsonObj["fields"] = 0;
    SecurityGuard::Rule rule = jsonObj.get<SecurityGuard::Rule>();
    EXPECT_TRUE(rule.eventId == 0);
    EXPECT_TRUE(rule.fields.empty());
    EXPECT_TRUE(rule.fieldsRelation == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling014, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["eventId"] = "";
    jsonObj["fields"] = 0;
    jsonObj["fieldsRelation"] = 0;
    SecurityGuard::Rule rule = jsonObj.get<SecurityGuard::Rule>();
    EXPECT_TRUE(rule.eventId == 0);
    EXPECT_TRUE(rule.fields.empty());
    EXPECT_TRUE(rule.fieldsRelation == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling015, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["eventId"] = 0;
    jsonObj["fields"] = 0;
    jsonObj["fieldsRelation"] = 0;
    SecurityGuard::Rule rule = jsonObj.get<SecurityGuard::Rule>();
    EXPECT_TRUE(rule.eventId == 0);
    EXPECT_TRUE(rule.fields.empty());
    EXPECT_TRUE(rule.fieldsRelation == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling016, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["eventId"] = 0;
    jsonObj["fields"] = 0;
    jsonObj["fieldsRelation"] = 0;
    SecurityGuard::Rule rule = jsonObj.get<SecurityGuard::Rule>();
    EXPECT_TRUE(rule.eventId == 0);
    EXPECT_TRUE(rule.fields.empty());
    EXPECT_TRUE(rule.fieldsRelation == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling017, TestSize.Level1)
{
    nlohmann::json jsonObj;
    nlohmann::json jsonField;
    jsonField["fieldName"] = "fieldName";
    jsonField["fieldType"] = "fieldType";
    jsonField["value"] = "value";
    jsonObj["eventId"] = 0;
    jsonObj["fields"] = {jsonField, jsonField};
    jsonObj["fieldsRelation"] = 0;
    SecurityGuard::Rule rule = jsonObj.get<SecurityGuard::Rule>();
    EXPECT_TRUE(rule.eventId == 0);
    EXPECT_TRUE(rule.fields.empty());
    EXPECT_TRUE(rule.fieldsRelation == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling018, TestSize.Level1)
{
    nlohmann::json jsonObj;
    nlohmann::json jsonField;
    jsonField["fieldName"] = "fieldName";
    jsonField["fieldType"] = "fieldType";
    jsonField["value"] = "value";
    jsonObj["eventId"] = 0;
    jsonObj["fields"] = {jsonField, jsonField};
    jsonObj["fieldsRelation"] = "fieldsRelation";
    SecurityGuard::Rule rule = jsonObj.get<SecurityGuard::Rule>();
    EXPECT_TRUE(rule.eventId == 0);
    EXPECT_TRUE(!rule.fields.empty());
    EXPECT_TRUE(rule.fieldsRelation == "fieldsRelation");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling019, TestSize.Level1)
{
    nlohmann::json jsonObj;
    SecurityGuard::BuildInDetectionCfg cfg = jsonObj.get<SecurityGuard::BuildInDetectionCfg>();
    EXPECT_TRUE(cfg.rules.empty());
    EXPECT_TRUE(cfg.rulesRelation == "");
    EXPECT_TRUE(cfg.trueResult == "");
    EXPECT_TRUE(cfg.falseResult == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling020, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["rules"] = 0;
    SecurityGuard::BuildInDetectionCfg cfg = jsonObj.get<SecurityGuard::BuildInDetectionCfg>();
    EXPECT_TRUE(cfg.rules.empty());
    EXPECT_TRUE(cfg.rulesRelation == "");
    EXPECT_TRUE(cfg.trueResult == "");
    EXPECT_TRUE(cfg.falseResult == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling021, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["rules"] = 0;
    jsonObj["rulesRelation"] = 0;
    SecurityGuard::BuildInDetectionCfg cfg = jsonObj.get<SecurityGuard::BuildInDetectionCfg>();
    EXPECT_TRUE(cfg.rules.empty());
    EXPECT_TRUE(cfg.rulesRelation == "");
    EXPECT_TRUE(cfg.trueResult == "");
    EXPECT_TRUE(cfg.falseResult == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling022, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["rules"] = 0;
    jsonObj["rulesRelation"] = 0;
    jsonObj["trueResult"] = 0;
    SecurityGuard::BuildInDetectionCfg cfg = jsonObj.get<SecurityGuard::BuildInDetectionCfg>();
    EXPECT_TRUE(cfg.rules.empty());
    EXPECT_TRUE(cfg.rulesRelation == "");
    EXPECT_TRUE(cfg.trueResult == "");
    EXPECT_TRUE(cfg.falseResult == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling023, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["rules"] = 0;
    jsonObj["rulesRelation"] = 0;
    jsonObj["trueResult"] = 0;
    jsonObj["falseResult"] = 0;
    SecurityGuard::BuildInDetectionCfg cfg = jsonObj.get<SecurityGuard::BuildInDetectionCfg>();
    EXPECT_TRUE(cfg.rules.empty());
    EXPECT_TRUE(cfg.rulesRelation == "");
    EXPECT_TRUE(cfg.trueResult == "");
    EXPECT_TRUE(cfg.falseResult == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling024, TestSize.Level1)
{
    nlohmann::json jsonObj;
    nlohmann::json jsonRule;
    nlohmann::json jsonField;
    jsonField["fieldName"] = "fieldName";
    jsonField["fieldType"] = "fieldType";
    jsonField["value"] = "value";
    jsonRule["eventId"] = 0;
    jsonRule["fields"] = {jsonField, jsonField};
    jsonRule["fieldsRelation"] = "fieldsRelation";
    jsonObj["rules"] = {jsonRule, jsonRule};
    jsonObj["rulesRelation"] = 0;
    jsonObj["trueResult"] = 0;
    jsonObj["falseResult"] = 0;
    SecurityGuard::BuildInDetectionCfg cfg = jsonObj.get<SecurityGuard::BuildInDetectionCfg>();
    EXPECT_TRUE(cfg.rules.empty());
    EXPECT_TRUE(cfg.rulesRelation == "");
    EXPECT_TRUE(cfg.trueResult == "");
    EXPECT_TRUE(cfg.falseResult == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling025, TestSize.Level1)
{
    nlohmann::json jsonObj;
    nlohmann::json jsonRule;
    nlohmann::json jsonField;
    jsonField["fieldName"] = "fieldName";
    jsonField["fieldType"] = "fieldType";
    jsonField["value"] = "value";
    jsonRule["eventId"] = 0;
    jsonRule["fields"] = {jsonField, jsonField};
    jsonRule["fieldsRelation"] = "fieldsRelation";
    jsonObj["rules"] = {jsonRule, jsonRule};
    jsonObj["rulesRelation"] = "rulesRelation";
    jsonObj["trueResult"] = 0;
    jsonObj["falseResult"] = 0;
    SecurityGuard::BuildInDetectionCfg cfg = jsonObj.get<SecurityGuard::BuildInDetectionCfg>();
    EXPECT_TRUE(cfg.rules.empty());
    EXPECT_TRUE(cfg.rulesRelation == "");
    EXPECT_TRUE(cfg.trueResult == "");
    EXPECT_TRUE(cfg.falseResult == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling026, TestSize.Level1)
{
    nlohmann::json jsonObj;
    nlohmann::json jsonRule;
    nlohmann::json jsonField;
    jsonField["fieldName"] = "fieldName";
    jsonField["fieldType"] = "fieldType";
    jsonField["value"] = "value";
    jsonRule["eventId"] = 0;
    jsonRule["fields"] = {jsonField, jsonField};
    jsonRule["fieldsRelation"] = "fieldsRelation";
    jsonObj["rules"] = {jsonRule, jsonRule};
    jsonObj["rulesRelation"] = "rulesRelation";
    jsonObj["trueResult"] = "trueResult";
    jsonObj["falseResult"] = 0;
    SecurityGuard::BuildInDetectionCfg cfg = jsonObj.get<SecurityGuard::BuildInDetectionCfg>();
    EXPECT_TRUE(cfg.rules.empty());
    EXPECT_TRUE(cfg.rulesRelation == "");
    EXPECT_TRUE(cfg.trueResult == "");
    EXPECT_TRUE(cfg.falseResult == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling027, TestSize.Level1)
{
    nlohmann::json jsonObj;
    nlohmann::json jsonRule;
    nlohmann::json jsonField;
    jsonField["fieldName"] = "fieldName";
    jsonField["fieldType"] = "fieldType";
    jsonField["value"] = "value";
    jsonRule["eventId"] = 0;
    jsonRule["fields"] = {jsonField, jsonField};
    jsonRule["fieldsRelation"] = "fieldsRelation";
    jsonObj["rules"] = {jsonRule, jsonRule};
    jsonObj["rulesRelation"] = "rulesRelation";
    jsonObj["trueResult"] = "trueResult";
    jsonObj["falseResult"] = "falseResult";
    SecurityGuard::BuildInDetectionCfg cfg = jsonObj.get<SecurityGuard::BuildInDetectionCfg>();
    EXPECT_TRUE(!cfg.rules.empty());
    EXPECT_TRUE(cfg.rulesRelation == "rulesRelation");
    EXPECT_TRUE(cfg.trueResult == "trueResult");
    EXPECT_TRUE(cfg.falseResult == "falseResult");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestUnmarshal001, testing::ext::TestSize.Level1)
{
    using namespace OHOS::Security::SecurityGuard;
    nlohmann::json jsonOb {
        {"version", "xxx"},
        {"releaseTime", "xxx"},
        {"detectMaxRecord", 999},
        {"uidMaxDnsRecord", 10},
        {"detectMaxTime", 86399},
        {"ipBlackList", {"1", "2"}},
        {"ipBlackListMock", {"xxx", "xxx"}},
        {"dnsBlackList", {"1", "2"}},
        {"number", {1, 2}}
    };
    std::vector<std::string> testVec {};
    std::vector<int64_t> testVecInt {};
    std::vector<int32_t> testVecIntS{};
    uint64_t data;
    int64_t dataInt;
    int32_t i32Data;
    uint32_t u32Data;

    EXPECT_TRUE(JsonCfg::Unmarshal(i32Data, jsonOb, "detectMaxRecord"));
    EXPECT_FALSE(JsonCfg::Unmarshal(i32Data, jsonOb, "releaseTime"));
    EXPECT_FALSE(JsonCfg::Unmarshal(i32Data, jsonOb, "isexist"));

    EXPECT_TRUE(JsonCfg::Unmarshal(u32Data, jsonOb, "detectMaxRecord"));
    EXPECT_FALSE(JsonCfg::Unmarshal(u32Data, jsonOb, "releaseTime"));
    EXPECT_FALSE(JsonCfg::Unmarshal(u32Data, jsonOb, "isexist"));

    EXPECT_TRUE(JsonCfg::Unmarshal(data, jsonOb, "detectMaxRecord"));
    EXPECT_FALSE(JsonCfg::Unmarshal(data, jsonOb, "releaseTime"));
    EXPECT_FALSE(JsonCfg::Unmarshal(data, jsonOb, "isexist"));

    EXPECT_TRUE(JsonCfg::Unmarshal(dataInt, jsonOb, "uidMaxDnsRecord"));
    EXPECT_FALSE(JsonCfg::Unmarshal(dataInt, jsonOb, "releaseTime"));
    EXPECT_FALSE(JsonCfg::Unmarshal(dataInt, jsonOb, "isexist"));

    EXPECT_TRUE(JsonCfg::Unmarshal(testVec, jsonOb, "ipBlackList"));
    EXPECT_FALSE(JsonCfg::Unmarshal(testVec, jsonOb, "isexist"));
    EXPECT_FALSE(JsonCfg::Unmarshal(testVec, jsonOb, "number"));

    EXPECT_TRUE(JsonCfg::Unmarshal(testVecInt, jsonOb, "number"));
    EXPECT_FALSE(JsonCfg::Unmarshal(testVecInt, jsonOb, "ipBlackList"));
    EXPECT_FALSE(JsonCfg::Unmarshal(testVecInt, jsonOb, "isexist"));

    EXPECT_TRUE(JsonCfg::Unmarshal(testVecIntS, jsonOb, "number"));
    EXPECT_FALSE(JsonCfg::Unmarshal(testVecIntS, jsonOb, "ipBlackList"));
    EXPECT_FALSE(JsonCfg::Unmarshal(testVecIntS, jsonOb, "isexist"));
}

}
