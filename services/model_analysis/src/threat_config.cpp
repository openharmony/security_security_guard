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

#include "threat_config.h"

namespace OHOS::Security::SecurityGuard {
ThreatConfig::ThreatConfig(const ThreatCfgSt &config)
    : threatId_(config.threatId),
      threatName_(config.threatName),
      version_(config.version),
      eventList_(config.eventList),
      computeModel_(config.computeModel)
{
}

uint32_t ThreatConfig::GetThreatId() const
{
    return threatId_;
}

const std::string &ThreatConfig::GetThreatName() const
{
    return threatName_;
}

uint32_t ThreatConfig::GetVersion() const
{
    return version_;
}

const std::vector<int64_t> &ThreatConfig::GetEventList() const
{
    return eventList_;
}

const std::string &ThreatConfig::GetComputeModel() const
{
    return computeModel_;
}
}