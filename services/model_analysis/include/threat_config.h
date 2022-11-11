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

#ifndef SECURITY_GUARD_THREAT_CONFIG_H
#define SECURITY_GUARD_THREAT_CONFIG_H

#include "model_cfg_marshalling.h"

namespace OHOS::Security::SecurityGuard {
class ThreatConfig {
public:
    explicit ThreatConfig(const ThreatCfgSt &config);
    uint32_t GetThreatId() const;
    const std::string &GetThreatName() const;
    uint32_t GetVersion() const;
    const std::vector<int64_t> &GetEventList() const;
    const std::string &GetComputeModel() const;

private:
    uint32_t threatId_{};
    std::string threatName_;
    uint32_t version_{};
    std::vector<int64_t> eventList_;
    std::string computeModel_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_THREAT_CONFIG_H
