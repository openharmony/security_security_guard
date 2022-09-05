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

#ifndef SECURITY_GUARD_EVENT_CONFIG_H
#define SECURITY_GUARD_EVENT_CONFIG_H

#include "model_cfg_marshalling.h"

namespace OHOS::Security::SecurityGuard {
class EventConfig {
public:
    explicit EventConfig(const EventCfgSt& config);
    EventConfig() = default;
    EventConfig(const EventConfig &config) = default;
    int64_t GetEventId() const;
    const std::string &GetEventName() const;
    uint32_t GetVersion() const;
    uint32_t GetEventType() const;
    uint32_t GetDataSensitivityLevel() const;
    uint32_t GetStorageRamNums() const;
    uint32_t GetStorageRomNums() const;

private:
    int64_t eventId_{};
    std::string eventName_{};
    uint32_t version_{};
    uint32_t eventType_{};
    uint32_t dataSensitivityLevel_{};
    uint32_t storageRamNums_{};
    uint32_t storageRomNums_{};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_EVENT_CONFIG_H
