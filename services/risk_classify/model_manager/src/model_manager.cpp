/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "model_manager.h"

#include <dlfcn.h>

#include "directory_ex.h"

#include "config_data_manager.h"
#include "preferences_wrapper.h"
#include "security_guard_log.h"
#include "model_manager_impl.h"
#include "database_manager.h"
#include "security_guard_define.h"

namespace OHOS::Security::SecurityGuard {
std::shared_ptr<IModelManager> ModelManager::modelManagerApi_ = std::make_shared<ModelManagerImpl>();

namespace {
    constexpr const char *AUDIT_SWITCH = "audit_switch";
    constexpr const char *PREFIX_MODEL_PATH = "/system/lib64/lib";
    constexpr int32_t AUDIT_SWITCH_OFF = 0;
    constexpr int32_t AUDIT_SWITCH_ON = 1;
    constexpr uint32_t AUDIT_MODEL = 3001000003;
}

void ModelManager::Init()
{
    std::vector<uint32_t> modelIds = ConfigDataManager::GetInstance().GetAllModelIds();
    ModelCfg cfg;
    for (uint32_t modelId : modelIds) {
        bool success = ConfigDataManager::GetInstance().GetModelConfig(modelId, cfg);
        if (!success) {
            continue;
        }
        SGLOGI("modelId is %{public}u, start_mode: %{public}u", modelId, cfg.startMode);
        if (cfg.startMode != START_ON_STARTUP) {
            continue;
        }
        if (cfg.modelId != AUDIT_MODEL) {
            (void) InitModel(modelId);
            continue;
        }
        if (PreferenceWrapper::GetInt(AUDIT_SWITCH, AUDIT_SWITCH_OFF) == AUDIT_SWITCH_ON) {
            SGLOGI("begin init audit model");
            (void) InitModel(modelId);
        }
    }
}

int32_t ModelManager::InitModel(uint32_t modelId)
{
    std::unordered_map<uint32_t, std::unique_ptr<ModelAttrs>>::iterator iter;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        iter = modelIdApiMap_.find(modelId);
        if (iter != modelIdApiMap_.end() && iter->second != nullptr && iter->second->GetModelApi() != nullptr) {
            iter->second->GetModelApi()->Release();
            modelIdApiMap_.erase(iter);
        }
    }

    ModelCfg cfg;
    bool success = ConfigDataManager::GetInstance().GetModelConfig(modelId, cfg);
    if (!success) {
        SGLOGE("the model not support, modelId=%{public}u", modelId);
        return NOT_FOUND;
    }
    std::string realPath;
    if (!PathToRealPath(cfg.path, realPath) || realPath.find(PREFIX_MODEL_PATH) != 0) {
        return FILE_ERR;
    }
    void *handle = dlopen(realPath.c_str(), RTLD_LAZY);
    if (handle == nullptr) {
        SGLOGE("modelId=%{public}u, open failed, reason:%{public}s", modelId, dlerror());
        return FAILED;
    }
    std::unique_ptr<ModelAttrs> attr = std::make_unique<ModelAttrs>();
    attr->SetHandle(handle);
    auto getModelApi = (GetModelApi)dlsym(handle, "GetModelApi");
    if (getModelApi == nullptr) {
        SGLOGE("get model api func is nullptr");
        return FAILED;
    }
    IModel *api = getModelApi();
    if (api == nullptr) {
        SGLOGE("get model api is nullptr");
        return FAILED;
    }
    attr->SetModelApi(api);
    int32_t ret = attr->GetModelApi()->Init(modelManagerApi_);
    if (ret != SUCCESS) {
        SGLOGE("model api init failed, ret=%{public}d", ret);
        return ret;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        modelIdApiMap_[modelId] = std::move(attr);
    }
    SGLOGI("init model success, modelId=%{public}u", modelId);
    return SUCCESS;
}

std::string ModelManager::GetResult(uint32_t modelId, const std::string &param)
{
    std::string result = "unknown";
    int32_t ret = InitModel(modelId);
    if (ret != SUCCESS) {
        return result;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto iter = modelIdApiMap_.find(modelId);
        if (iter == modelIdApiMap_.end() || iter->second == nullptr || iter->second->GetModelApi() == nullptr) {
            SGLOGI("the model has not been initialized, begin init, modelId=%{public}u", modelId);
            return result;
        }
        result = iter->second->GetModelApi()->GetResult(modelId, param);
    }
    ModelCfg config;
    bool success = ConfigDataManager::GetInstance().GetModelConfig(modelId, config);
    if (success && config.startMode == START_ON_DEMAND) {
        Release(modelId);
    }
    return result;
}

int32_t ModelManager::SubscribeResult(uint32_t modelId, std::shared_ptr<IModelResultListener> listener)
{
    int32_t ret = InitModel(modelId);
    if (ret != SUCCESS) {
        return ret;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = modelIdApiMap_.find(modelId);
    if (iter == modelIdApiMap_.end() || iter->second == nullptr || iter->second->GetModelApi() == nullptr) {
        SGLOGI("the model has not been initialized, modelId=%{public}u", modelId);
        return FAILED;
    }

    return iter->second->GetModelApi()->SubscribeResult(listener);
}

void ModelManager::Release(uint32_t modelId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = modelIdApiMap_.find(modelId);
    if (iter == modelIdApiMap_.end()) {
        SGLOGI("the model has not been initialized, modelId=%{public}u", modelId);
        return;
    }

    if (iter->second == nullptr || iter->second->GetModelApi() == nullptr) {
        SGLOGI("the model attr is nullptr, modelId=%{public}u", modelId);
        modelIdApiMap_.erase(iter);
        return;
    }

    iter->second->GetModelApi()->Release();
    modelIdApiMap_.erase(iter);
}
} // namespace OHOS::Security::SecurityGuard
