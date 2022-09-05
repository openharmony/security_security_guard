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

#include "event_config.h"

namespace OHOS::Security::SecurityGuard {
EventConfig::EventConfig(const EventCfgSt& config)
    : eventId_(config.eventId),
      eventName_(config.eventName),
      version_(config.version),
      eventType_(config.eventType),
      dataSensitivityLevel_(config.dataSensitivityLevel),
      storageRamNums_(config.storageRamNums),
      storageRomNums_(config.storageRomNums)
{
}

int64_t EventConfig::GetEventId() const
{
    return eventId_;
}

const std::string &EventConfig::GetEventName() const
{
    return eventName_;
}

uint32_t EventConfig::GetVersion() const
{
    return version_;
}

uint32_t EventConfig::GetEventType() const
{
    return eventType_;
}

uint32_t EventConfig::GetDataSensitivityLevel() const
{
    return dataSensitivityLevel_;
}

uint32_t EventConfig::GetStorageRamNums() const
{
    return storageRamNums_;
}

uint32_t EventConfig::GetStorageRomNums() const
{
    return storageRomNums_;
}
}