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

#include "bigdata.h"

#include "hisysevent.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    const std::string CALLER_PID = "CALLER_PID";
    const std::string CALL_TIME = "CALL_TIME";
    const std::string EVENT_SIZE = "EVENT_SIZE";
    const std::string EVENT_INFO = "EVENT_INFO";
    const std::string RISK_STATUS = "RISK_STATUS";
}

void BigData::ReportObatinDataEvent(const ObatinDataEvent &event)
{
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::SECURITY_GUARD, "OBTAIN_DATA",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, CALLER_PID, event.pid,
        CALL_TIME, event.time, EVENT_SIZE, event.size);
}

void BigData::ReportClassifyEvent(const ClassifyEvent &event)
{
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::SECURITY_GUARD, "RISK_ANALYSIS",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, CALLER_PID, event.pid,
        CALL_TIME, event.time, EVENT_INFO, event.eventInfo, RISK_STATUS, event.status);
}
}