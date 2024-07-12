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

#define private public
#define protected public
#include "base_config.h"
#include "config_data_manager.h"
#include "config_define.h"
#include "config_manager.h"
#include "config_operator.h"
#include "config_subscriber.h"
#include "event_config.h"
#include "model_cfg_marshalling.h"
#include "model_config.h"
#include "local_app_config.h"
#include "global_app_config.h"
#include "rdb_helper.h"
#include "app_info_rdb_helper.h"
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

namespace {
    constexpr int SUCCESS = 0;
    constexpr int FAILED = 1;
    constexpr size_t MAXAPPSIZE = 500;
}

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

HWTEST_F(SecurityGuardConfigManagerTest, TestConfigSubsciber001, TestSize.Level1)
{
    TimeEventRelatedCallBack callBack = nullptr;
    bool success = ConfigSubscriber::RegisterTimeEventRelatedCallBack(callBack);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestEventConfig001, TestSize.Level1)
{
    EventConfig config;
    bool success = config.Load(INIT_MODE);
    EXPECT_TRUE(success);
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

HWTEST_F(SecurityGuardConfigManagerTest, TestModelConfig001, TestSize.Level1)
{
    ModelConfig config;
    bool success = config.Load(INIT_MODE);
    EXPECT_TRUE(success);
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

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig000, TestSize.Level1)
{
    LocalAppConfig config;
    bool success = config.Load(INIT_MODE);
    EXPECT_TRUE(success);
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), QueryAllAppInfo(An<std::vector<AppInfo> &>())).
        WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), InsertAppInfo(
        An<const AppInfo &>())).WillRepeatedly(Return(SUCCESS));
    config.stream_ = std::ifstream("/data/test/unittest/resource/local_app_attribute_update.json", std::ios::in);
    EXPECT_TRUE(config.stream_.is_open());
    EXPECT_FALSE(!config.stream_);
    success = config.Parse();
    EXPECT_TRUE(success);
    success = config.Update();
    EXPECT_TRUE(success);
}


HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig001, TestSize.Level1)
{
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), QueryAllAppInfo(An<std::vector<AppInfo> &>())).
        WillRepeatedly(Return(FAILED));
    LocalAppConfig config;
    config.stream_.open("/data/test/unittest/resource/local_app_attribute_update.json");
    EXPECT_TRUE(config.stream_.is_open());
    bool success = config.Parse();
    EXPECT_TRUE(success);
    success = config.Update();
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig002, TestSize.Level1)
{
    LocalAppConfig config;
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), InsertAllAppInfo(
        An<const std::vector<AppInfo> &>())).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), QueryAllAppInfo(An<std::vector<AppInfo> &>())).
        WillRepeatedly(Return(SUCCESS));
    std::ofstream out("/data/test/unittest/resource/local_app_attribute_update.json");
    std::string errtmp = R"({
    "version":"001",
    "apps":""
    })";
    out << errtmp << std::endl;
    config.stream_.open("/data/test/unittest/resource/local_app_attribute_update.json");
    EXPECT_TRUE(config.stream_.is_open());
    bool success = config.Parse();
    EXPECT_TRUE(success);
    success = config.Update();
    EXPECT_FALSE(success);
    std::string tmp = R"({
    "version":"001",
    "apps":[
        {
            "name":"com.sohu.harmonynews",
            "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
            "attribute":["monitoring"],
            "isUpdate":1
        },
        {
            "name":"com.sohu.harmonynews",
            "fingerprint":"ED2D188FACD5EB93248B287366324F6A12DF3A7B8D464C89FDD88FF1588C6596",
            "attribute":[],
            "isUpdate":1
        }
    ]
    })";
    std::ofstream out1("/data/test/unittest/resource/local_app_attribute_update.json");
    out1 << tmp << std::endl;
    config.stream_.open("/data/test/unittest/resource/local_app_attribute_update.json");
    EXPECT_TRUE(config.stream_.is_open());
    success = config.Parse();
    EXPECT_TRUE(success);
    success = config.Update();
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig003, TestSize.Level1)
{
    LocalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001"
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig004, TestSize.Level1)
{
    LocalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps":"111"
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig005, TestSize.Level1)
{
    LocalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": []
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_TRUE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig006, TestSize.Level1)
{
    LocalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "name":"",
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
                "attribute":["monitoring"],
                "isUpdate":1
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig007, TestSize.Level1)
{
    LocalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "name":"",
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
                "attribute":["monitoring"],
                "isUpdate":2
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig008, TestSize.Level1)
{
    LocalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "name":"com.sohu.harmonynews",
                "attribute":["monitoring"],
                "isUpdate":1
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig009, TestSize.Level1)
{
    LocalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
                "attribute":["monitoring"],
                "isUpdate":1
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig010, TestSize.Level1)
{
    LocalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "name":"com.sohu.harmonynews",
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
                "isUpdate":1
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig012, TestSize.Level1)
{
    LocalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "name":"com.sohu.harmonynews",
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
                "attribute":["monitoring"]
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig013, TestSize.Level1)
{
    LocalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "name":"com.sohu.harmonynews",
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
                "attribute":["monitoringL"],
                "isUpdate":1
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig014, TestSize.Level1)
{
    LocalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "name":"com.sohu.harmonynews",
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
                "attribute":"monitoringL",
                "isUpdate":1
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig015, TestSize.Level1)
{
    LocalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "name":"com.sohu.harmonynews",
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
                "attribute":["monitoring", "payment", "malicious"],
                "isUpdate":1
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_TRUE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig017, TestSize.Level1)
{
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), QueryAllAppInfo).WillOnce(Return(FAILED)).WillRepeatedly(
        [] (std::vector<AppInfo> &infos) {
            AppInfo info{};
            info.appName = "com.sohu.harmonynews";
            infos.emplace_back(info);
            return SUCCESS;
        });
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), DeleteAppInfoByNameAndGlobbalFlag(
        An<const std::string &>(), An<int>())).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), InsertAppInfo(
        An<const AppInfo &>())).WillRepeatedly(Return(SUCCESS));
    LocalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "name":"com.sohu.harmonynews",
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
                "attribute":["monitoring", "payment", "malicious"],
                "isUpdate":1
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_TRUE(success);
    config.UpdateInfoToDb(configs);
    EXPECT_TRUE(success);
    config.UpdateInfoToDb(configs);
    EXPECT_TRUE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig018, TestSize.Level1)
{
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), QueryAllAppInfo).WillRepeatedly(
        [] (std::vector<AppInfo> &infos) {
            AppInfo info{};
            info.appName = "com.sohu.harmonynews";
            info.isGlobalApp = 0;
            infos.emplace_back(info);
            return SUCCESS;
        });
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), InsertAppInfo).WillOnce(Return(SUCCESS)).
        WillRepeatedly(Return(FAILED));
    LocalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "name":"com.sohu.harmonynews",
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
                "attribute":["monitoring", "payment", "malicious"],
                "isUpdate":1
            },
            {
                "name":"ttttt",
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
                "attribute":["monitoring", "payment", "malicious"],
                "isUpdate":1
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_TRUE(success);
    success = config.UpdateInfoToDb(configs);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig019, TestSize.Level1)
{
    LocalAppConfig conf;
    AppInfo config {};
    config.appName = "a";
    config.isUpdate = 1;
    AppInfo dbConfig {};
    dbConfig.appName = "a";
    bool isFind;
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), InsertAppInfo).WillRepeatedly([](
        const AppInfo & info) {
        return FAILED;
    });
    EXPECT_FALSE(conf.IsNeedUpdate(config, dbConfig, isFind));
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig020, TestSize.Level1)
{
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), QueryAllAppInfo).WillRepeatedly(
        [] (std::vector<AppInfo> &infos) {
            AppInfo info{};
            info.appName = "com.sohu.harmonynews";
            info.isGlobalApp = 0;
            infos.emplace_back(info);
            return SUCCESS;
        });
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), InsertAppInfo).WillOnce(Return(SUCCESS)).
        WillRepeatedly(Return(FAILED));
    LocalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "name":"com.sohu.harmonynews",
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
                "attribute":["monitoring", "payment", "malicious"],
                "isUpdate":1
            },
            {
                "name":"ttttt",
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
                "attribute":["monitoring", "payment", "malicious"],
                "isUpdate":1
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_TRUE(success);
    success = config.UpdateInfoToDb(configs);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig021, TestSize.Level1)
{
    LocalAppConfig config;
    bool success = config.Load(INIT_MODE);
    EXPECT_TRUE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestLocalAppConfig022, TestSize.Level1)
{
    LocalAppConfig config;
    std::vector<AppInfo> configs;
    nlohmann::json::array_t arr;
    std::vector<std::string> attrs = {"monitoring"};
    for (size_t i = 0; i < MAXAPPSIZE + 1; i++) {
        nlohmann::json jsonObj {
            {"name", std::to_string(i)},
            {"fingerprint", "C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A"},
            {"attribute", attrs},
            {"isUpdate", 1}
        };
        arr.push_back(jsonObj);
    }
    nlohmann::json jsonOb {
        {"apps", arr}
    };
    std::string jsonStr = jsonOb.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_TRUE(success);
    EXPECT_TRUE(configs.size() == MAXAPPSIZE + 1);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig000, TestSize.Level1)
{
    GlobalAppConfig config;
    bool success = config.Load(INIT_MODE);
    EXPECT_TRUE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig001, TestSize.Level1)
{
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), DeleteAppInfoByIsGlobalApp(
        An<int>())).WillRepeatedly(Return(FAILED));
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), InsertAllAppInfo(
        An<const std::vector<AppInfo> &>())).WillRepeatedly(Return(FAILED));
    GlobalAppConfig config;
    config.stream_.open("/data/test/unittest/resource/global_app_attribute_update.json");
    EXPECT_TRUE(config.stream_.is_open());
    bool success = config.Parse();
    EXPECT_TRUE(success);
    success = config.Update();
    EXPECT_FALSE(success);
}


HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig002, TestSize.Level1)
{
    GlobalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001"
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig003, TestSize.Level1)
{
    GlobalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001"
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig004, TestSize.Level1)
{
    GlobalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps":"111"
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig005, TestSize.Level1)
{
    GlobalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": []
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_TRUE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig006, TestSize.Level1)
{
    GlobalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "name":"",
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
                "attribute":["monitoring"]
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig007, TestSize.Level1)
{
    GlobalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "name":"",
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC517572",
                "attribute":["monitoring"]
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig008, TestSize.Level1)
{
    GlobalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "name":"com.sohu.harmonynews",
                "attribute":["monitoring"]
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig009, TestSize.Level1)
{
    GlobalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
                "attribute":["monitoring"]
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig010, TestSize.Level1)
{
    GlobalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "name":"com.sohu.harmonynews",
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A"
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig011, TestSize.Level1)
{
    GlobalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "name":"com.sohu.harmonynews",
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
                "attribute":["monitoringL"]
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig012, TestSize.Level1)
{
    GlobalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "name":"com.sohu.harmonynews",
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
                "attribute":"monitoringL"
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig013, TestSize.Level1)
{
    GlobalAppConfig config;
    std::vector<AppInfo> configs;
    std::string jsonStr = R"({
        "version":"001",
        "apps": [
            {
                "name":"com.sohu.harmonynews",
                "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
                "attribute":["monitoring", "payment", "malicious"]
            }
        ]
    })";
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_TRUE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig014, TestSize.Level1)
{
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), DeleteAppInfoByIsGlobalApp(
        An<int>())).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), InsertAllAppInfo(
        An<const std::vector<AppInfo> &>())).WillRepeatedly(Return(SUCCESS));
    GlobalAppConfig config;
    config.stream_.open("/data/test/unittest/resource/global_app_attribute_update.json");
    EXPECT_TRUE(config.stream_.is_open());
    bool success = config.Parse();
    EXPECT_TRUE(success);
    success = config.Update();
    EXPECT_TRUE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig015, TestSize.Level1)
{
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), DeleteAppInfoByIsGlobalApp(
        An<int>())).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(AppInfoRdbHelper::GetInstance(), InsertAllAppInfo(
        An<const std::vector<AppInfo> &>())).WillRepeatedly(Return(SUCCESS));
    std::ofstream out("/data/test/unittest/resource/global_app_attribute_update.json");
    std::string errTmp = R"({
    "version":"001",
    "apps":""
    })";
    out << errTmp << std::endl;
    GlobalAppConfig config;
    config.stream_.open("/data/test/unittest/resource/global_app_attribute_update.json");
    EXPECT_TRUE(config.stream_.is_open());
    bool success = config.Parse();
    EXPECT_TRUE(success);
    success = config.Update();
    EXPECT_FALSE(success);
    std::string tmp = R"({
    "version":"001",
    "apps":[
        {
            "name":"com.sohu.harmonynews",
            "fingerprint":"C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A",
            "attribute":["monitoring"]
        },
        {
            "name":"com.sohu.harmonynews",
            "fingerprint":"ED2D188FACD5EB93248B287366324F6A12DF3A7B8D464C89FDD88FF1588C6596",
            "attribute":[]
        }
    ]
    })";
    out << tmp << std::endl;
    success = config.Update();
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig016, TestSize.Level1)
{
    GlobalAppConfig config;
    std::vector<AppInfo> configs;
    nlohmann::json::array_t arr;
    std::vector<std::string> attrs = {"monitoring"};
    for (size_t i = 0; i < MAXAPPSIZE + 1; i++) {
        nlohmann::json jsonObj {
            {"name", std::to_string(i)},
            {"fingerprint", "C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A"},
            {"attribute", attrs},
        };
        arr.push_back(jsonObj);
    }
    nlohmann::json jsonOb {
        {"apps", arr}
    };
    std::string jsonStr = jsonOb.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_TRUE(success);
    EXPECT_TRUE(configs.size() == MAXAPPSIZE + 1) ;
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig017, TestSize.Level1)
{
    GlobalAppConfig config;
    bool success = config.Update();
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig018, TestSize.Level1)
{
    GlobalAppConfig config;
    std::vector<AppInfo> configs;
    nlohmann::json::array_t arr;
    std::vector<std::string> attrs = {"monitoring"};
    for (size_t i = 0; i < MAXAPPSIZE + 1; i++) {
        nlohmann::json jsonObj {
            {"name", std::to_string(i)},
            {"fingerprint", "C8C9687FD68B738417ED2BFA6B91609A3F63720D30369130DEB802DC5175724A"},
            {"attribute", attrs},
            {"isUpdate", 1},
        };
        arr.push_back(jsonObj);
    }
    nlohmann::json jsonOb {
        {"apps", arr}
    };
    std::string jsonStr = jsonOb.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    nlohmann::json extraJson = nlohmann::json::parse(jsonStr, nullptr, false);
    EXPECT_FALSE(extraJson.is_discarded());
    bool success = config.ParseAppListConfig(configs, extraJson);
    EXPECT_TRUE(success);
    EXPECT_TRUE(configs.size() == MAXAPPSIZE + 1);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestGlobalAppConfig019, TestSize.Level1)
{
    GlobalAppConfig config;
    bool success = config.Load(INIT_MODE);
    EXPECT_TRUE(success);
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
}
