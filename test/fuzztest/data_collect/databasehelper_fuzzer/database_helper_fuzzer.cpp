/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "database_helper_fuzzer.h"

#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "securec.h"
#include <string_ex.h>

#define private public
#define protected public
#include "event_define.h"
#include "acquire_data_subscribe_manager.h"
#include "acquire_data_callback_proxy.h"
#include "data_collect_manager_callback_proxy.h"
#include "data_collect_manager_service.h"
#include "data_collect_manager_idl_stub.h"
#include "security_event_query_callback_proxy.h"
#include "database_helper.h"
#include "database_manager.h"
#include "database.h"
#include "risk_event_rdb_helper.h"
#include "store_define.h"
#undef private
#undef prtected

using namespace OHOS::Security::SecurityGuard;
namespace {
    constexpr int MAX_STRING_SIZE = 1024;
}
namespace OHOS {

bool DatabaseHelperFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int64_t eventId = fdp.ConsumeIntegral<int64_t>();
    std::vector<int64_t> eventIds{eventId};
    std::string string = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    DatabaseHelper helper{string};
    SecEvent event = {
        .eventId = eventId,
        .version = string,
    };
    std::vector<SecEvent> events{event};
    GenericValues value{};
    helper.Init();
    helper.InsertEvent(event);
    helper.QueryAllEvent(events);
    helper.QueryRecentEventByEventId(eventId, event);
    helper.QueryRecentEventByEventId(eventIds, events);
    helper.QueryEventByEventId(eventId, events);
    helper.QueryEventByEventId(eventIds, events);
    helper.QueryEventByEventIdAndDate(eventIds, events, string, string);
    helper.QueryEventByEventType(eventId, events);
    helper.QueryEventByLevel(eventId, events);
    helper.QueryEventByOwner(string, events);
    helper.CountAllEvent();
    helper.CountEventByEventId(eventId);
    helper.DeleteOldEventByEventId(eventId, eventId);
    helper.DeleteAllEventByEventId(eventId);
    helper.FlushAllEvent();
    helper.QueryEventBase(value, events);
    helper.CreateTable();
    helper.SetValuesBucket(event, value);
    helper.Release();
    return true;
}

void RiskEventRdbHelperFuzzTest()
{
    Security::SecurityGuard::RiskEventRdbHelper::GetInstance().Init();
}
}  // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::RiskEventRdbHelperFuzzTest();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::DatabaseHelperFuzzTest(data, size);
    return 0;
}