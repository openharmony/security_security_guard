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

#include "data_format.h"

#include "json_cfg.h"
#include "model_analysis_define.h"
#include "model_cfg_marshalling.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr uint32_t MAX_CONTENT_SIZE = 900;
}

bool DataFormat::CheckRiskContent(std::string content)
{
    auto size = static_cast<uint32_t>(content.size());
    if (size > MAX_CONTENT_SIZE) {
        SGLOGE("size error, size=%{public}u", size);
        return false;
    }

    json jsonObj = json::parse(content, nullptr, false);
    if (jsonObj.is_discarded()) {
        SGLOGE("json parse error");
        return false;
    }

    EventContentSt eventContentSt;
    if (!Unmarshal(eventContentSt.status, jsonObj, EVENT_CONTENT_STATUS_KEY)) {
        SGLOGE("status parse error");
        return false;
    }
    if (!Unmarshal(eventContentSt.cred, jsonObj, EVENT_CONTENT_CRED_KEY)) {
        SGLOGE("cred parse error");
        return false;
    }
    if (!Unmarshal(eventContentSt.extra, jsonObj, EVENT_CONTENT_EXTRA_KEY)) {
        SGLOGE("extra parse error");
        return false;
    }
    return true;
}
}