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

#include "task_manager.h"

#include "thread_pool.h"

namespace OHOS::Security::SecurityGuard {
TaskManager &TaskManager::GetInstance()
{
    static TaskManager instance;
    return instance;
}

bool TaskManager::PushTask(std::shared_ptr<BaseTask> &task)
{
    if (task == nullptr) {
        return false;
    }

    if (!ThreadPool::GetInstance().PushTask(task)) {
        return false;
    }
    task->OnPrepare();
    return true;
}

TaskManager::TaskManager()
{
    ThreadPool::GetInstance().InitThreadPool();
}
}