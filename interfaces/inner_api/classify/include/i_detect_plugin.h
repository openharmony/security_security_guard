/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef I_DETECT_PLUGIN_H
#define I_DETECT_PLUGIN_H
#include <string>
#include <cstdint>

namespace OHOS::Security::SecurityGuard {
class IDetectPlugin {
public:
    virtual ~IDetectPlugin() = default;
    virtual bool Init() = 0;
    virtual void Destroy() = 0;
    virtual void HandleEvent(int64_t eventId, const std::string& content, const std::string& metadata) = 0;
};

typedef IDetectPlugin* (*CreateDetectPlugin)();
} // namespace OHOS::Security::SecurityGuard
#endif