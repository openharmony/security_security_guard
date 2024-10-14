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

#include "security_guard_model_manager_test.h"


#include "file_ex.h"
#include "gmock/gmock.h"

#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "i_config_operate.h"
#define private public
#define protected public
#include "config_data_manager.h"
#include "i_model.h"
#include "model_manager.h"
#include "model_manager_impl.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityGuardTest;

namespace OHOS::Security::SecurityGuardTest {
namespace {
}

void SecurityGuardModelManagerTest::SetUpTestCase()
{
}

void SecurityGuardModelManagerTest::TearDownTestCase()
{
}

void SecurityGuardModelManagerTest::SetUp()
{
}

void SecurityGuardModelManagerTest::TearDown()
{
}

class MockModel : public IModel {
public:
    MOCK_METHOD1(Init, int32_t(std::shared_ptr<IModelManager>));
    MOCK_METHOD2(GetResult, std::string(uint32_t, const std::string &));
    MOCK_METHOD1(SubscribeResult, int32_t(std::shared_ptr<IModelResultListener>));
    MOCK_METHOD0(Release, void());
};

class MockModelManager : public IModelManager {
public:
    MOCK_METHOD0(GetConfigOperate, std::shared_ptr<IConfigOperate>());
    MOCK_METHOD1(GetDbOperate, std::shared_ptr<IDbOperate>(std::string));
    MOCK_METHOD2(SubscribeDb, int32_t(std::vector<int64_t>, std::shared_ptr<IDbListener>));
    MOCK_METHOD2(UnSubscribeDb, int32_t(std::vector<int64_t>, std::shared_ptr<IDbListener>));
};

class MockDbOperate : public IDbOperate {
public:
    MOCK_METHOD1(InsertEvent, int(SecEvent&));
    MOCK_METHOD1(QueryAllEvent, int(std::vector<SecEvent> &));
    MOCK_METHOD2(QueryRecentEventByEventId, int(int64_t, SecEvent &));
    MOCK_METHOD2(QueryRecentEventByEventId, int(const std::vector<int64_t> &, std::vector<SecEvent> &));
    MOCK_METHOD2(QueryEventByEventId, int(int64_t, std::vector<SecEvent> &));
    MOCK_METHOD2(QueryEventByEventId, int(std::vector<int64_t> &, std::vector<SecEvent> &));
    MOCK_METHOD2(QueryEventByEventType, int(int32_t, std::vector<SecEvent> &));
    MOCK_METHOD2(QueryEventByLevel, int(int32_t, std::vector<SecEvent> &));
    MOCK_METHOD2(QueryEventByOwner, int(std::string, std::vector<SecEvent> &));
    MOCK_METHOD0(CountAllEvent, int64_t());
    MOCK_METHOD1(CountEventByEventId, int64_t(int64_t));
    MOCK_METHOD2(DeleteOldEventByEventId, int(int64_t, int64_t));
    MOCK_METHOD1(DeleteAllEventByEventId, int(int64_t));
};

class MockConfigOperate : public IConfigOperate {
public:
    MOCK_METHOD2(GetModelConfig, bool(uint32_t, ModelCfg &));
    MOCK_METHOD2(GetEventConfig, bool(int64_t, EventCfg &));
};

static void TestModel001(const char *path)
{
    void *handle = dlopen(path, RTLD_LAZY);
    EXPECT_FALSE(handle == nullptr);
    auto getModelApi = (GetModelApi)dlsym(handle, "GetModelApi");
    EXPECT_FALSE(getModelApi == nullptr);
    IModel *api = getModelApi();
    EXPECT_FALSE(api == nullptr);
    int32_t ret = api->Init(nullptr);
    EXPECT_EQ(ret, -1);
    dlclose(handle);
    handle = nullptr;
}

HWTEST_F(SecurityGuardModelManagerTest, TestModelManagerImpl001, TestSize.Level1)
{
    auto impl = std::make_shared<ModelManagerImpl>();
    std::shared_ptr<IDbOperate> oper = impl->GetDbOperate("risk_event");
    EXPECT_FALSE(oper == nullptr);
    oper = impl->GetDbOperate("audit_event");
    EXPECT_FALSE(oper == nullptr);
    oper = impl->GetDbOperate("test_table");
    EXPECT_TRUE(oper == nullptr);
}

HWTEST_F(SecurityGuardModelManagerTest, TestModelManagerInit001, TestSize.Level1)
{
    std::vector<uint32_t> emptyVector{};
    std::vector<uint32_t> vector{0};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetAllModelIds).Times(AtLeast(5)).WillOnce(Return(emptyVector))
        .WillRepeatedly(Return(vector));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetModelConfig).Times(AtLeast(5)).WillOnce(Return(false))
        .WillOnce([](uint32_t modelId, ModelCfg &config) {
            config.startMode = 0;
            return true;
        })
        .WillOnce([](uint32_t modelId, ModelCfg &config) {
            config.startMode = 1;
            config.modelId = 0;
            return true;
        })
        .WillRepeatedly([](uint32_t modelId, ModelCfg &config) {
            config.startMode = 1;
            config.modelId = 3001000003;
            return true;
        });
    ModelManager::GetInstance().Init();
    ModelManager::GetInstance().Init();
    ModelManager::GetInstance().Init();
    ModelManager::GetInstance().Init();
    ModelManager::GetInstance().Init();
}

HWTEST_F(SecurityGuardModelManagerTest, TestModelManagerInitModel001, TestSize.Level1)
{
    MockModel *model = new MockModel();
    EXPECT_CALL(*model, Release()).Times(1);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetModelConfig).Times(1).WillOnce(Return(false));
    std::unique_ptr<ModelAttrs> attr = std::make_unique<ModelAttrs>();
    attr->SetModelApi(model);
    ModelManager::GetInstance().modelIdApiMap_[8888] = std::move(attr);
    ModelManager::GetInstance().InitModel(8888);
}

HWTEST_F(SecurityGuardModelManagerTest, TestModelManagerInitModel002, TestSize.Level1)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetModelConfig).Times(AtLeast(6))
        .WillOnce([](uint32_t modelId, ModelCfg &config) {
            config.path = "/system/lib64/sg_test";
            return true;
        })
        .WillOnce([](uint32_t modelId, ModelCfg &config) {
            config.path = "/system/lib64/libsg_collector_sdk.z.so";
            return true;
        })
        .WillOnce([](uint32_t modelId, ModelCfg &config) {
            config.path = "/system/lib64/libsg_system_risk_detection.z.so";
            return true;
        })
        .WillOnce([](uint32_t modelId, ModelCfg &config) {
            config.startMode = NOT_SUPPORT;
            return false;
        })
        .WillOnce([](uint32_t modelId, ModelCfg &config) {
            config.startMode = NOT_SUPPORT;
            return true;
        })
        .WillRepeatedly([](uint32_t modelId, ModelCfg &config) {
            config.startMode = START_ON_DEMAND;
            return true;
        });
    ModelManager::GetInstance().InitModel(9999);
    ModelManager::GetInstance().GetResult(9999, "");
    ModelManager::GetInstance().SubscribeResult(9999, nullptr);
    ModelManager::GetInstance().Release(9999);
    ModelManager::GetInstance().InitModel(9999);
    ModelManager::GetInstance().GetResult(9999, "");
    ModelManager::GetInstance().SubscribeResult(9999, nullptr);
    ModelManager::GetInstance().Release(9999);
    ModelManager::GetInstance().InitModel(9999);
    ModelManager::GetInstance().GetResult(9999, "");
    ModelManager::GetInstance().GetResult(9999, "");
    ModelManager::GetInstance().GetResult(9999, "");
    ModelManager::GetInstance().SubscribeResult(9999, nullptr);
    ModelManager::GetInstance().Release(9999);
}

HWTEST_F(SecurityGuardModelManagerTest, TestDeviceCompletenessModel001, TestSize.Level1)
{
    TestModel001("/system/lib64/libsg_system_risk_detection.z.so");
}

HWTEST_F(SecurityGuardModelManagerTest, TestDeviceCompletenessModel002, TestSize.Level1)
{
    void *handle = dlopen("/system/lib64/libsg_system_risk_detection.z.so", RTLD_LAZY);
    EXPECT_FALSE(handle == nullptr);
    auto getModelApi = (GetModelApi)dlsym(handle, "GetModelApi");
    EXPECT_FALSE(getModelApi == nullptr);
    IModel *api = getModelApi();
    EXPECT_FALSE(api == nullptr);
    std::shared_ptr<MockModelManager> mockObj = std::make_shared<MockModelManager>();
    std::shared_ptr<MockDbOperate> mockOpt = std::make_shared<MockDbOperate>();
    std::shared_ptr<MockConfigOperate> mockCfg = std::make_shared<MockConfigOperate>();
    EXPECT_CALL(*mockObj, GetDbOperate).WillOnce(Return(nullptr)).WillRepeatedly(Return(mockOpt));
    EXPECT_CALL(*mockObj, GetConfigOperate).WillOnce(Return(nullptr)).WillOnce(Return(mockCfg));
    int32_t ret = api->Init(mockObj);
    EXPECT_EQ(ret, -1);
    ret = api->Init(mockObj);
    EXPECT_EQ(ret, -1);
    ret = api->Init(mockObj);
    EXPECT_EQ(ret, 0);
    dlclose(handle);
    handle = nullptr;
}
}