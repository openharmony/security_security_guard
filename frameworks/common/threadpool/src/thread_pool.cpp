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

#include "thread_pool.h"

namespace OHOS::Security::SecurityGuard {
ThreadPool::ThreadPool()
    : isStopped_(false)
{
}

ThreadPool &ThreadPool::GetInstance()
{
    static ThreadPool instance;
    return instance;
}

void ThreadPool::InitThreadPool()
{
    const static uint32_t maxThreadNums = 5;
    for (uint32_t i = 0; i < maxThreadNums; i++) {
        workerThread_.emplace_back([this] {
            while (true) {
                std::shared_ptr<BaseTask> task;
                {
                    std::unique_lock<std::mutex> lock(mutex_);
                    condVar_.wait(lock, [this] { return isStopped_ || !taskQueue_.empty(); });
                    if (isStopped_ && taskQueue_.empty()) {
                        return;
                    }
                    task = taskQueue_.front();
                    taskQueue_.pop();
                }
                task->OnExecute();
            }
        });
    }
}

bool ThreadPool::PushTask(const std::shared_ptr<BaseTask> &task)
{
    const static uint32_t maxTaskNums = 5;
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (taskQueue_.size() > maxTaskNums || isStopped_) {
            return false;
        }

        taskQueue_.emplace(task);
    }
    condVar_.notify_one();
    return true;
}

ThreadPool::~ThreadPool()
{
    {
        std::unique_lock<std::mutex> lock(mutex_);
        isStopped_ = true;
    }
    condVar_.notify_all();
    for (std::thread &workerThread: workerThread_) {
        if (workerThread.joinable()) {
            workerThread.join();
        }
    }
}
}