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

#ifndef SECURITY_GUARD_I_MODEL_MANAGER_IMP_H
#define SECURITY_GUARD_I_MODEL_MANAGER_IMP_H

#include <unordered_map>
#include <set>
#include <mutex>

#include "i_model_manager.h"

namespace OHOS::Security::SecurityGuard {
class ModelManagerImpl : public IModelManager {
public:
    ModelManagerImpl() = default;
    ~ModelManagerImpl() override = default;
    std::shared_ptr<IDbOperate> GetDbOperate(std::string table) override;
    std::shared_ptr<IConfigOperate> GetConfigOperate() override;
    int32_t SubscribeDb(std::vector<int64_t> eventIds, std::shared_ptr<IDbListener> listener) override;
    int32_t UnSubscribeDb(std::vector<int64_t> eventIds, std::shared_ptr<IDbListener> listener) override;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_I_MODEL_MANAGER_IMP_H
