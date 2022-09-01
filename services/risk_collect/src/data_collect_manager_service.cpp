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

#include "load_db_task.h"
#include "security_guard_log.h"
#include "task_manager.h"

namespace OHOS::Security::SecurityGuard {
REGISTER_SYSTEM_ABILITY_BY_ID(DataCollectManagerService, DATA_COLLECT_MANAGER_SA_ID, true);

DataCollectManagerService::DataCollectManagerService(int32_t saId, bool runOnCreate)
    : SystemAbility(saId, runOnCreate)
{
    SGLOGW("%{public}s", __func__);
}

void DataCollectManagerService::OnStart()
{
    SGLOGE("%{public}s", __func__);
    if (!Publish(this)) {
        SGLOGE("Publish error");
        return;
    }

    std::shared_ptr<BaseTask> loadDbTask = std::make_shared<LoadDbTask>();
    bool isSuccess = TaskManager::GetInstance().PushTask(loadDbTask);
    if (!isSuccess) {
        SGLOGE("LOAD DB TASK ERROR");
    }
}

void DataCollectManagerService::OnStop()
{
}
}