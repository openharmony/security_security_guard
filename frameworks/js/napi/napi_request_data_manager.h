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

#ifndef NAPI_REQUEST_DATA_MANAGER_H
#define NAPI_REQUEST_DATA_MANAGER_H

#include <mutex>
#include <unordered_map>

#include "security_guard_napi.h"

namespace OHOS::Security::SecurityGuard {
class NapiRequestDataManager {
public:
    static NapiRequestDataManager& GetInstance();
    std::shared_ptr<RequestSecurityEventInfoContext> GetContext(napi_env env);
    std::shared_ptr<RequestSecurityEventInfoContext> GetContext(napi_env env, bool &isExist);
    void DeleteContext(napi_env env);

private:
    std::unordered_map<napi_env, std::shared_ptr<RequestSecurityEventInfoContext>> envContextMap_;
    std::mutex mutex_;
    NapiRequestDataManager() = default;
    ~NapiRequestDataManager() = default;
};
} // OHOS::Security::SecurityGuard

#endif // NAPI_REQUEST_DATA_MANAGER_H
