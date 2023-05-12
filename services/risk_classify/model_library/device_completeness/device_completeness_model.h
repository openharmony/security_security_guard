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

#ifndef SECURITY_GUARD_DEVICE_COMPLETENESS_MODEL_H
#define SECURITY_GUARD_DEVICE_COMPLETENESS_MODEL_H

#include "i_model.h"

#include "nlohmann/json.hpp"

namespace OHOS::Security::SecurityGuard {
using CONTENT_STATUS = enum {
    RISK,
    SAFE
};

using CONTENT_RELIABLITY = enum {
    INCREDIBLE,
    CREDIBLE
};

using EventContent = struct {
    uint32_t status;
    uint32_t cred;
    std::string extra;
};

void to_json(nlohmann::json &jsonObj, const EventContent &eventContent)
{
    jsonObj = nlohmann::json {
        { "status", eventContent.status },
        { "cred", eventContent.cred },
        { "extra", eventContent.extra }
    };
}

void from_json(const nlohmann::json &jsonObj, EventContent &eventContent)
{
    if (jsonObj.find("status") == jsonObj.end() || jsonObj.find("cred") == jsonObj.end() ||
        jsonObj.find("extra") == jsonObj.end()) {
        return;
    }

    if (!jsonObj.at("status").is_number() || !jsonObj.at("cred").is_number() ||
        !jsonObj.at("extra").is_string()) {
        return;
    }
    eventContent.status = jsonObj.at("status").get<uint32_t>();
    eventContent.cred = jsonObj.at("cred").get<uint32_t>();
    eventContent.extra = jsonObj.at("extra").get<std::string>();
}

class DeviceCompletenessModel : public IModel {
public:
    ~DeviceCompletenessModel() override;
    int32_t Init(std::shared_ptr<IModelManager> api) override;
    std::string GetResult() override;
    int32_t SubscribeResult(std::shared_ptr<IModelResultListener> listener) override;
    void Release() override;

private:
    std::string RiskAnalysis(std::vector<SecEvent> &eventData);
    std::shared_ptr<IDbOperate> dbOpt_;
};
} // OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_DEVICE_COMPLETENESS_MODEL_H