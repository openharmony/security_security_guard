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

#ifndef SECURITY_GUARD_DATA_COLLECT_MANAGER_STUB_H
#define SECURITY_GUARD_DATA_COLLECT_MANAGER_STUB_H

#include "iremote_stub.h"

#include <future>

#include "i_data_collect_manager.h"
#include "security_guard_define.h"

namespace OHOS::Security::SecurityGuard {
class DataCollectManagerStub : public IRemoteStub<IDataCollectManager> {
public:
    DataCollectManagerStub() = default;
    ~DataCollectManagerStub() override = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
        MessageOption& option) override;

private:
    static ErrorCode HandleDataCollectCmd(MessageParcel &data, MessageParcel &reply);
    static ErrorCode HandleDataRequestCmd(MessageParcel &data, MessageParcel &reply);
    static ErrorCode ParseEventList(std::string eventList, std::vector<int64_t> &eventListVec);
    static void PushDataCollectTask(sptr<IRemoteObject> &object, std::string eventList, std::string devId,
        std::shared_ptr<std::promise<int32_t>> &promise);
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_DATA_COLLECT_MANAGER_STUB_H
