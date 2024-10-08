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

#include "risk_collect_fuzzer.h"

#include <string>

#include "securec.h"

#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#define private public
#define protected public
#include "config_data_manager.h"
#include "database_manager.h"
#include "uevent_notify.h"
#include "data_format.h"
#include "kernel_interface_adapter.h"
#undef private
#undef protected

using namespace OHOS::Security::SecurityGuard;

namespace OHOS {
void DataFormatFuzzTest()
{
    std::string test = "test";
    DataFormat::CheckRiskContent(test);
    uint32_t oversize = 1000;
    std::string oversizeString(oversize, 'c');
    DataFormat::CheckRiskContent(oversizeString);

    RequestCondition reqCondition;
    std::string condition1 = "{\"eventId\":0}";
    std::string condition2 = "{\"eventId\":[\"t\", \"e\", \"s\", \"t\"]}";
    std::string condition3 = "{\"eventId\":[1, 2, 3, 4]}";
    std::string condition4 = "{\"beginTime\":1}";
    std::string condition5 = "{\"beginTime\":\"0001\"}";
    std::string condition6 = "{\"endTime\":1}";
    std::string condition7 = "{\"endTime\":\"0001\"}";
    DataFormat::ParseConditions(test, reqCondition);
    DataFormat::ParseConditions(condition1, reqCondition);
    DataFormat::ParseConditions(condition2, reqCondition);
    DataFormat::ParseConditions(condition3, reqCondition);
    DataFormat::ParseConditions(condition4, reqCondition);
    DataFormat::ParseConditions(condition5, reqCondition);
    DataFormat::ParseConditions(condition6, reqCondition);
    DataFormat::ParseConditions(condition7, reqCondition);
}

void KernelInterfaceAdapterFuzzTest()
{
    KernelInterfaceAdapter adapter;
    adapter.Socket(0, 0, 0);

    struct sockaddr addr = {};
    adapter.Bind(0, nullptr, 0);
    adapter.Bind(0, &addr, sizeof(addr));

    struct pollfd fds = {};
    adapter.Poll(&fds, 0, 0);
    adapter.Poll(nullptr, 0, 0);
    
    char buffer[1] = {};
    adapter.Recv(0, buffer, sizeof(buffer), 0);
    adapter.Recv(0, nullptr, 0, 0);

    const char* pathName = "test";
    adapter.Open(pathName, 0);
    const char* pathName2 = "/proc/kernel_sg";
    adapter.Open(pathName2, 0);

    char buffer2[1] = {};
    adapter.Write(0, buffer2, sizeof(buffer2));
    adapter.Write(0, nullptr, 0);
}
}  // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::DataFormatFuzzTest();
    OHOS::KernelInterfaceAdapterFuzzTest();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    return 0;
}
