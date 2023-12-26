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

#ifndef SECURITY_GUARD_TASK_HANDLER_H
#define SECURITY_GUARD_TASK_HANDLER_H

#include <future>
#include <string>

#include "singleton.h"
#include "thread_pool.h"

namespace OHOS::Security::SecurityGuard {
class TaskHandler : public DelayedSingleton<TaskHandler> {
public:
    using Task = std::function<void()>;
    TaskHandler();
    ~TaskHandler() override;
    void AddTask(Task &task);
    void AddMinorsTask(Task &task);

private:
    OHOS::ThreadPool pool_;
    OHOS::ThreadPool minorsPool_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_TASK_HANDLER_H
