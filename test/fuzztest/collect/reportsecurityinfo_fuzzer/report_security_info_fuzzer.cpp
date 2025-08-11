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
#include <fuzzer/FuzzedDataProvider.h>
#include "securec.h"

#include "security_guard_define.h"
#include "sg_collect_client.h"

#undef private

extern "C" int32_t ReportSecurityInfo(const struct EventInfoSt *info);

namespace OHOS {
namespace {
constexpr int MAX_STRING_SIZE = 1024;
}
bool ReportSecurityInfoFuzzTest(const uint8_t *data, size_t size)
{
    int64_t eventId = rand() % (size + 1);
    EventInfoSt info;
    info.eventId = eventId;
    std::string version(reinterpret_cast<const char *>(data), size);
    info.version = version.c_str();
    uint32_t cpyLen = size >= CONTENT_MAX_LEN ? CONTENT_MAX_LEN - 1 : static_cast<uint32_t>(size);
    (void)memcpy_s(info.content, CONTENT_MAX_LEN, data, cpyLen);
    info.contentLen = cpyLen;
    ReportSecurityInfo(&info);
    return true;
}

bool ReportSecurityInfoAsyncFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider &fdp)
{
    EventInfoSt info;
    info.eventId = fdp.ConsumeIntegral<int64_t>();
    std::string str = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    info.version = str.c_str();
    uint32_t cpyLen = size >= CONTENT_MAX_LEN ? CONTENT_MAX_LEN - 1 : static_cast<uint32_t>(size);
    (void)memcpy_s(info.content, CONTENT_MAX_LEN, data, cpyLen);
    info.contentLen = cpyLen;
    ReportSecurityInfoAsync(&info);
    return true;
}

bool SecurityGuardConfigUpdateFuzzTest(FuzzedDataProvider &fdp)
{
    int32_t fd = fdp.ConsumeIntegral<int32_t>();
    std::string name = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE).c_str();
    SecurityGuardConfigUpdate(fd, name.c_str());
    return true;
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    /* Run your code on date */
    OHOS::ReportSecurityInfoFuzzTest(data, size);
    OHOS::ReportSecurityInfoAsyncFuzzTest(data, size, fdp);
    OHOS::SecurityGuardConfigUpdateFuzzTest(fdp);
    return 0;
}
