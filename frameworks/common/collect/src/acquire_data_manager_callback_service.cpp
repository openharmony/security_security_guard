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
#include <memory>
#include "ffrt.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
// 每实例独立锁：跨实例不互相阻塞。锁实现仅在 cpp 内可见，头文件不暴露 ffrt。
// 锁序：notifyMutex_ -> callbackMutex_，反向获取视为死锁。
struct AcquireDataManagerCallbackService::CallbackMutex {
    ffrt::mutex notifyMutex_;
    ffrt::mutex callbackMutex_;
};

AcquireDataManagerCallbackService::AcquireDataManagerCallbackService()
    : mutexes_(std::make_unique<CallbackMutex>()) {}

AcquireDataManagerCallbackService::~AcquireDataManagerCallbackService() = default;

void AcquireDataManagerCallbackService::RegistCallBack(
    std::function<void(const SecurityCollector::Event &event)> callback)
{
    std::lock_guard<ffrt::mutex> lock(mutexes_->callbackMutex_);
    if (callback == nullptr) {
        return;
    }
    callback_ = callback;
}

void AcquireDataManagerCallbackService::ClearCallBack()
{
    // OnNotify 在"拷贝回调 + 执行用户回调"整段期间都持有 notifyMutex_，
    // 因此这里取 notifyMutex_ 即可等待本 stub 上所有在途 OnNotify 跑完整段循环。
    // 锁序为 notifyMutex_ -> callbackMutex_，与 OnNotify 一致，不会死锁。
    std::lock_guard<ffrt::mutex> execLock(mutexes_->notifyMutex_);
    std::lock_guard<ffrt::mutex> slotLock(mutexes_->callbackMutex_);
    callback_ = nullptr;
}

int32_t AcquireDataManagerCallbackService::OnNotify(const std::vector<SecurityCollector::Event> &events)
{
    // 持续持有 notifyMutex_ 贯穿"拷贝回调 + 执行回调"整段。
    // ClearCallBack 取同一把锁，故其返回后不会有任何 OnNotify 处于拷贝点之后或循环体内，
    // 不存在 ClearCallBack 在拷贝与执行之间插入并返回、
    // 导致回调仍然访问已释放状态的竞态窗口。
    std::lock_guard<ffrt::mutex> execLock(mutexes_->notifyMutex_);
    std::function<void(const SecurityCollector::Event &event)> callback;
    {
        std::lock_guard<ffrt::mutex> slotLock(mutexes_->callbackMutex_);
        callback = callback_;
    }
    if (callback == nullptr) {
        SGLOGE("callback is null");
        return FAILED;
    }
    // 回调在锁内串行执行：保持"同一时刻只回调一次"的语义，同时用户回调反向调用
    // Subscribe/Unsubscribe 时只取 DataCollectManager 的 mutex_，与本锁无环，不会自死锁
    for (const auto &it : events) {
        SGLOGD("callback eventId=%{public}" PRId64, it.eventId);
        callback(it);
    }
    return SUCCESS;
}
}