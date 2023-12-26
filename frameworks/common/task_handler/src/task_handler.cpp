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

#include "task_handler.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    const int THREAD_NUMS = 5;
    const int MAX_TASK_NUMS = 1000;
    const int MINORS_THREAD_NUMS = 1;
    const int MINORS_MAX_TASK_NUMS = 500;
}

TaskHandler::TaskHandler()
{
    pool_.Start(THREAD_NUMS);
    pool_.SetMaxTaskNum(MAX_TASK_NUMS);
    minorsPool_.Start(MINORS_THREAD_NUMS);
    minorsPool_.SetMaxTaskNum(MINORS_MAX_TASK_NUMS);
}

TaskHandler::~TaskHandler()
{
    pool_.Stop();
    minorsPool_.Stop();
}

void TaskHandler::AddTask(Task &task)
{
    pool_.AddTask(task);
}

void TaskHandler::AddMinorsTask(Task &task)
{
    minorsPool_.AddTask(task);
}
}