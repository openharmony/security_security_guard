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

#include "data_collect_manager_stub.h"

#include "data_collect_task.h"
#include "data_distribute_task.h"
#include "data_format.h"
#include "i_data_collect_manager.h"
#include "model_cfg_marshalling.h"
#include "security_guard_log.h"
#include "task_manager.h"

namespace OHOS::Security::SecurityGuard {
int32_t DataCollectManagerStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    SGLOGD("%{public}s", __func__);
    do {
        if (IDataCollectManager::GetDescriptor() != data.ReadInterfaceToken()) {
            SGLOGE("descriptor error");
            break;
        }

        switch (code) {
            case CMD_DATA_COLLECT: {
                return HandleDataCollectCmd(data, reply);
            }
            case CMD_DATA_REQUEST: {
                return HandleDataRequestCmd(data, reply);
            }
            default: {
                break;
            }
        }
    } while (false);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ErrorCode DataCollectManagerStub::HandleDataCollectCmd(MessageParcel &data, MessageParcel &reply)
{
    SGLOGD("%{public}s", __func__);
    uint32_t expected = sizeof(int64_t);
    uint32_t actual = data.GetReadableBytes();
    if (expected >= actual) {
        SGLOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    int64_t eventId = data.ReadInt64();
    std::string version = data.ReadString();
    std::string time = data.ReadString();
    std::string content = data.ReadString();
    if (!DataFormat::CheckRiskContent(content)) {
        SGLOGE("CheckRiskContent error");
        return BAD_PARAM;
    }
    SGLOGE("Collect Data SUCCESS");
    SGLOGE("eventId=%{public}ld, version=%{public}s, date=%{public}s, content=%{public}s",
        eventId, version.c_str(), time.c_str(), content.c_str());
    EventDataSt eventData {
        .eventId = eventId,
        .version = version,
        .date = time,
        .content = content
    };
    std::shared_ptr<BaseTask> task = std::make_shared<DataCollectTask>(eventData);
    bool isSuccess = TaskManager::GetInstance().PushTask(task);
    if (!isSuccess) {
        SGLOGE("TASK ERROR");
        return TASK_ERR;
    }
    return SUCCESS;
}

ErrorCode DataCollectManagerStub::HandleDataRequestCmd(MessageParcel &data, MessageParcel &reply)
{
    SGLOGD("%{public}s", __func__);
    uint32_t expected = 0;
    uint32_t actual = data.GetReadableBytes();
    if (expected >= actual) {
        SGLOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    std::string devId = data.ReadString();
    std::string eventList = data.ReadString();
    auto object = data.ReadRemoteObject();
    if (object == nullptr) {
        SGLOGE("object is nullptr");
        return BAD_PARAM;
    }
    SGLOGE("GET ObtaindataRequest SUCCESS");
    SGLOGE("devId=%{public}s, eventList=%{public}s", devId.c_str(), eventList.c_str());
    std::shared_ptr<BaseTask> task = std::make_shared<DataDistributeTask>(devId, eventList, object);
    bool isSuccess = TaskManager::GetInstance().PushTask(task);
    if (!isSuccess) {
        SGLOGE("TASK ERROR");
        return TASK_ERR;
    }
    return SUCCESS;
}
}