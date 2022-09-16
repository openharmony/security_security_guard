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

#include "report_security_info_fuzzer.h"

#include <string>

#include "event_info.h"
#include "sg_collect_client.h"

#undef private

using namespace OHOS::Security::SecurityGuard;
namespace OHOS {
bool ReportSecurityInfoFuzzTest(const uint8_t* data, size_t size)
{
    int64_t eventId = rand() % (size + 1);
    std::string version(reinterpret_cast<const char*>(data), size);
    std::string content(reinterpret_cast<const char*>(data), size);
    std::shared_ptr<EventInfo> eventInfo = std::make_shared<EventInfo>(eventId, version, content);
    NativeDataCollectKit::ReportSecurityInfo(eventInfo);
    return true;
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::ReportSecurityInfoFuzzTest(data, size);
    return 0;
}
