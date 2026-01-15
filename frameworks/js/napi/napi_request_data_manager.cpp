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

#include "napi_request_data_manager.h"

#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
NapiRequestDataManager& NapiRequestDataManager::GetInstance()
{
    static NapiRequestDataManager instance;
    return instance;
}

std::shared_ptr<RequestSecurityEventInfoContext> NapiRequestDataManager::GetContext(napi_env env)
{
    bool isExist = false;
    return GetContext(env, isExist);
}

std::shared_ptr<RequestSecurityEventInfoContext> NapiRequestDataManager::GetContext(napi_env env, bool &isExist)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = envContextMap_.find(env);
    if (iter != envContextMap_.end()) {
        SGLOGI("find the env entry");
        isExist = true;
        return iter->second;
    }

    auto context = std::make_shared<RequestSecurityEventInfoContext>();
    envContextMap_[env] = context;
    isExist = false;
    return context;
}

void NapiRequestDataManager::DeleteContext(napi_env env)
{
    SGLOGI("begin delete the env entry");
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = envContextMap_.find(env);
    if (iter != envContextMap_.end()) {
        if (iter->second != nullptr) {
            napi_delete_reference(env, iter->second->endCallback);
            iter->second->endCallback = nullptr;
            napi_delete_reference(env, iter->second->dataCallback);
            iter->second->dataCallback = nullptr;
            napi_delete_reference(env, iter->second->errorCallback);
            iter->second->errorCallback = nullptr;
            napi_delete_reference(env, iter->second->ref);
            iter->second->ref = nullptr;
        }
        envContextMap_.erase(iter);
    }
}

uint32_t NapiRequestDataManager::AddDataCallback(napi_env env)
{
    std::lock_guard<std::mutex> lock(envQuerierMutex_);
    auto iter = envQuerierMap_.find(env);
    if (iter != envQuerierMap_.end()) {
        envQuerierMap_[env]++;
        return iter->second;
    }
    uint32_t dataCallbackSize = 1;
    envQuerierMap_[env] = dataCallbackSize;
    return dataCallbackSize;
}
 
uint32_t NapiRequestDataManager::DelDataCallback(napi_env env)
{
    std::lock_guard<std::mutex> lock(envQuerierMutex_);
    auto iter = envQuerierMap_.find(env);
    if (iter != envQuerierMap_.end()) {
        envQuerierMap_.erase(iter);
    }
    return 0;
}
 
bool NapiRequestDataManager::GetDataCallback(napi_env env)
{
    std::lock_guard<std::mutex> lock(envQuerierMutex_);
    auto iter = envQuerierMap_.find(env);
    if (iter != envQuerierMap_.end()) {
        return true;
    }
    return false;
}
} // OHOS::Security::SecurityGuard