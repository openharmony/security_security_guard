/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <string>
#include "model_manager.h"

namespace OHOS::Security::SecurityGuard {
std::shared_ptr<IModelManager> ModelManager::modelManagerApi_ = nullptr;

void ModelManager::Init() {}

int32_t ModelManager::InitModel(uint32_t modelId)
{
    (void)modelId;
    return 0;
}

std::string ModelManager::GetResult(uint32_t modelId, const std::string &param)
{
    (void)modelId;
    (void)param;
    return "";
}

int32_t ModelManager::SubscribeResult(uint32_t modelId, std::shared_ptr<IModelResultListener> listener)
{
    (void)modelId;
    (void)listener;
    return 0;
}

void ModelManager::Release(uint32_t modelId)
{
    (void)modelId;
}

int32_t ModelManager::StartSecurityModel(uint32_t modelId, const std::string &param)
{
    (void)modelId;
    (void)param;
    return 0;
}
} // namespace OHOS::Security::SecurityGuard
