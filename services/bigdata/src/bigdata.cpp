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
    constexpr const char* CALLER_PID = "CALLER_PID";
    constexpr const char* CALL_TIME = "CALL_TIME";
    constexpr const char* EVENT_SIZE = "EVENT_SIZE";
    constexpr const char* EVENT_INFO = "EVENT_INFO";
    constexpr const char* RISK_STATUS = "RISK_STATUS";
    constexpr const char* EVENT_ID = "EVENT_ID";
    constexpr const char* SUB_RET = "SUB_RET";
    constexpr const char* UNSUB_RET = "UNSUB_RET";
    constexpr const char* CONFIG_PATH = "CONFIG_PATH";
    constexpr const char* RET = "RET";
}

void BigData::ReportObtainDataEvent(const ObtainDataEvent &event)
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

void BigData::ReportSgSubscribeEvent(const SgSubscribeEvent &event)
{
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::SECURITY_GUARD, "SG_EVENT_SUBSCRIBE",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, CALLER_PID, event.pid,
        CALL_TIME, event.time, EVENT_ID, event.eventId, SUB_RET, event.ret);
}

void BigData::ReportSgUnsubscribeEvent(const SgUnsubscribeEvent &event)
{
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::SECURITY_GUARD, "SG_EVENT_UNSUBSCRIBE",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, CALLER_PID, event.pid,
        CALL_TIME, event.time, UNSUB_RET, event.ret);
}

void BigData::ReportConfigUpdateEvent(const ConfigUpdateEvent &event)
{
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::SECURITY_GUARD, "SG_UPDATE_CONFIG",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, CONFIG_PATH, event.path,
        CALL_TIME, event.time, RET, event.ret);
}

void BigData::ReportSetMuteEvent(const SgSubscribeEvent &event)
{
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::SECURITY_GUARD, "SG_EVENT_SET_MUTE",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, CALLER_PID, event.pid,
        CALL_TIME, event.time, EVENT_ID, event.eventId, RET, event.ret);
}

void BigData::ReportSetUnMuteEvent(const SgSubscribeEvent &event)
{
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::SECURITY_GUARD, "SG_EVENT_SET_UNMUTE",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, CALLER_PID, event.pid,
        CALL_TIME, event.time, EVENT_ID, event.eventId, RET, event.ret);
}
}