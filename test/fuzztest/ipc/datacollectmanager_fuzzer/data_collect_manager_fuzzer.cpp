/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "data_collect_manager_fuzzer.h"

#include <string>

#include "data_collect_manager_callback_service.h"
#include "data_collect_manager_service.h"
#include "security_guard_log.h"


namespace OHOS::Security::SecurityGuard {
DataCollectManagerService g_service(DATA_COLLECT_MANAGER_SA_ID, true);
constexpr int32_t REMAINDER_VALUE = 2;

void OnRemoteRequestFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(IDataCollectManager::GetDescriptor());
    if (size % REMAINDER_VALUE == 0) {
        // handle data collect cmd
        int64_t eventId = static_cast<int64_t>(size);
        std::string version(reinterpret_cast<const char *>(data), size);
        std::string time(reinterpret_cast<const char *>(data), size);
        std::string content(reinterpret_cast<const char *>(data), size);
        datas.WriteInt64(eventId);
        datas.WriteString(version);
        datas.WriteString(time);
        datas.WriteString(content);
        g_service.OnRemoteRequest(DataCollectManagerStub::CMD_DATA_COLLECT, datas, reply, option);
        return;
    }
    // handle data request cmd
    std::string deviceId(reinterpret_cast<const char *>(data), size);
    std::string conditions(reinterpret_cast<const char *>(data), size);
    datas.WriteString(deviceId);
    datas.WriteString(conditions);
    RequestRiskDataCallback func = [] (std::string &devId, std::string &riskData, uint32_t status,
        const std::string &errMsg) -> int32_t {
        SGLOGI("DataCollectManagerCallbackService called");
        return 0;
    };
    sptr<IRemoteObject> callback = new (std::nothrow) DataCollectManagerCallbackService(func);
    datas.WriteRemoteObject(callback);
    g_service.OnRemoteRequest(DataCollectManagerStub::CMD_DATA_REQUEST, datas, reply, option);
}
}  // namespace OHOS::Security::SecurityGuard

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::Security::SecurityGuard::OnRemoteRequestFuzzTest(data, size);
    return 0;
}
