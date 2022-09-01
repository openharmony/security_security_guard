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

#ifndef SECURITY_GUARD_BASE_EVENT_ID_H
#define SECURITY_GUARD_BASE_EVENT_ID_H

#include "i_collect_info.h"
#include "model_cfg_marshalling.h"

namespace OHOS::Security::SecurityGuard {
class BaseEventId : public ICollectInfo {
public:
    explicit BaseEventId(int64_t eventId);
    ~BaseEventId() override = default;
    void ToJson(Json &jsonObj) const override;
    void FromJson(const Json &jsonObj) override;
    std::string ToString() const override;
    std::string GetPrimeKey() const override;
    bool Push(const EventDataSt &eventDataSt);
    bool GetCacheData(std::vector<EventDataSt>& vector);
    const std::vector<EventDataSt> &GetEventVec() const;

private:
    int64_t eventId_;
    std::vector<EventDataSt> eventVec_;
    void ReplaceOldestData(const EventDataSt &eventDataSt);
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_BASE_EVENT_ID_H
