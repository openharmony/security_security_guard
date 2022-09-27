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

#include "data_collect_manager_service.h"

#include <thread>
#include <vector>

#include "string_ex.h"

#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "task_handler.h"
#include "data_manager_wrapper.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int TWO_ARGS = 2;
}

REGISTER_SYSTEM_ABILITY_BY_ID(DataCollectManagerService, DATA_COLLECT_MANAGER_SA_ID, true);

DataCollectManagerService::DataCollectManagerService(int32_t saId, bool runOnCreate)
    : SystemAbility(saId, runOnCreate)
{
    SGLOGW("%{public}s", __func__);
}

void DataCollectManagerService::OnStart()
{
    SGLOGI("%{public}s", __func__);
    if (!Publish(this)) {
        SGLOGE("Publish error");
        return;
    }

    TaskHandler::Task task = [] {
        DataManagerWrapper::GetInstance().LoadCacheData();
    };
    TaskHandler::GetInstance()->AddTask(task);
}

void DataCollectManagerService::OnStop()
{
}

int DataCollectManagerService::Dump(int fd, const std::vector<std::u16string>& args)
{
    SGLOGI("DataCollectManagerService Dump");
    if (fd < 0) {
        return BAD_PARAM;
    }

    std::string arg0 = ((args.size() == 0) ? "" : Str16ToStr8(args.at(0)));
    if (arg0.compare("-h") == 0) {
        dprintf(fd, "Usage:\n");
        dprintf(fd, "       -h: command help\n");
        dprintf(fd, "       -i <EVENT_ID>: dump special eventId\n");
    } else if (arg0.compare("-i") == 0) {
        if (args.size() < TWO_ARGS) {
            return BAD_PARAM;
        }

        int64_t eventId;
        bool isSuccess = SecurityGuardUtils::StrToI64(Str16ToStr8(args.at(1)), eventId);
        if (!isSuccess) {
            return BAD_PARAM;
        }

        DumpEventInfo(fd, eventId);
    }
    return ERR_OK;
}

void DataCollectManagerService::DumpEventInfo(int fd, int64_t eventId)
{
    std::vector<int64_t> eventIds {eventId};
    std::vector<EventDataSt> eventData;
    ErrorCode code = DataManagerWrapper::GetInstance().GetEventDataById(eventIds, eventData);
    if (code != SUCCESS || eventData.size() == 0) {
        SGLOGE("GetEventDataById error");
        return;
    }
    sort(eventData.begin(), eventData.end(),
        [] (const EventDataSt &a, const EventDataSt &b) -> bool {
            return a.date > b.date;
        });
    dprintf(fd, "eventId : %ld\n", eventData.at(0).eventId);
    dprintf(fd, "report time : %s\n", eventData.at(0).date.c_str());
    dprintf(fd, "report version : %s\n", eventData.at(0).version.c_str());
}
}