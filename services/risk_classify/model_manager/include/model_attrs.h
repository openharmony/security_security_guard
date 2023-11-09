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

#ifndef SECURITY_GUARD_MODEL_ATTRS_H
#define SECURITY_GUARD_MODEL_ATTRS_H

#include <dlfcn.h>

#include "i_model.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
class ModelAttrs {
public:
    ~ModelAttrs()
    {
        SGLOGI("~ModelAttrs");
        if (api_ != nullptr) {
            delete api_;
            api_ = nullptr;
        }
        if (handle_ != nullptr) {
            dlclose(handle_);
            handle_ = nullptr;
        }
    };

    void SetHandle(void *handle) { handle_ = handle; };
    void SetModelApi(IModel *api) { api_ = api; };
    void *GetHandle() { return handle_; };
    IModel *GetModelApi() { return api_; };

private:
    void *handle_;
    IModel *api_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_I_MODEL_MANAGER_API_H
