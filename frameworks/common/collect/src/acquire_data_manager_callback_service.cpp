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

#include "acquire_data_manager_callback_service.h"
#include <cinttypes>
#include "ffrt.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    // 对外头文件不暴露锁实现，锁仅在本文件内保护 callback_ 槽位与回调执行串行化
    ffrt::mutex g_callbackMutex;
    ffrt::mutex g_notifyMutex;
}

void AcquireDataManagerCallbackService::RegistCallBack(
    std::function<void(const SecurityCollector::Event &event)> callback)
{
    std::lock_guard<ffrt::mutex> lock(g_callbackMutex);
    if (callback == nullptr) {
        return;
    }
    callback_ = callback;
}

void AcquireDataManagerCallbackService::ClearCallback()
{
    // OnNotify 在“拷贝回调 + 执行用户回调”整段期间都持有 g_notifymutex，
    // 因此这里取g_notifymutex 即可等待所有在途OnNotify跑完整段循环。
    // 锁序为g_notifymutex->g_callbackmutex,与下发OnNotify一致，不会死锁。
    std::lock_guard<ffrt::mutex> execLock(g_notifyMutex);
    std::lock_guard<ffrt::mutex> slotLock(g_callbackMutex);
    callback_ = nullptr;
}

int32_t AcquireDataManagerCallbackService::OnNotify(const std::vector<SecurityCollector::Event> &events)
{
    // 持续持有 g_notifyMutex 贯穿“拷贝回调 + 执行回调”整段。
    // ClearCallback 取同一把锁，故其返回后不会有任何OnNotify 处于拷贝点之后或循环体内，
    // 不存在ClearCallback在拷贝与执行之间插入并返回。
    // 导致回调仍取访问已经释放状态的竞态窗口。
    std::lock_guard<ffrt::mutex> execLock(g_notifyMutex);
    std::function<void(const SecurityCollector::Event &event)> callback;
    {
        std::lock_guard<ffrt::mutex> slotLock(g_callbackMutex);
        callback = callback_;
    }
    if (callback == nullptr) {
        SGLOGE("callback is null");
        return FAILED;
    }
    // 回调在叶子锁下串行执行：保持"同一时刻只回调一次"的语义，同时用户回调反向调用
    // Subscribe/Unsubscribe 时只取 DataCollectManager 的 mutex_，与本锁无环，不会自死锁
    std::lock_guard<ffrt::mutex> lock(g_notifyMutex);
    for (const auto &it : events) {
        SGLOGD("callback eventId=%{public}" PRId64, it.eventId);
        callback(it);
    }
    return SUCCESS;
}
}