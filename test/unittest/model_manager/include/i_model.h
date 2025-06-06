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

#ifndef SECURITY_GUARD_I_MODEL_H
#define SECURITY_GUARD_I_MODEL_H

#include <memory>
#include <string>

#include "i_model_manager.h"
#include "i_model_result_listener.h"

namespace OHOS::Security::SecurityGuard {
class IModel {
public:
    virtual ~IModel() = default;
    virtual int32_t Init(std::shared_ptr<IModelManager> api) = 0;
    virtual std::string GetResult(uint32_t modelId, const std::string &param) = 0;
    virtual int32_t SubscribeResult(std::shared_ptr<IModelResultListener> listener) = 0;
    virtual void Release() = 0;
    virtual int32_t StartSecurityModel(uint32_t modelId, const std::string &param) {return 0;};
};

typedef IModel* (*GetModelApi)();
} // OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_I_MODEL_H
