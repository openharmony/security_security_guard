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

#ifndef SECURITY_GUARD_ACQUIRE_DATA_MANAGER_CALBACK_SERVICE_H
#define SECURITY_GUARD_ACQUIRE_DATA_MANAGER_CALBACK_SERVICE_H
#include <functional>
#include <memory>
#include "acquire_data_manager_callback_stub.h"
#include "i_collector_subscriber.h"

namespace OHOS::Security::SecurityGuard {
class AcquireDataManagerCallbackService : public AcquireDataManagerCallbackStub {
public:
    AcquireDataManagerCallbackService();
    ~AcquireDataManagerCallbackService() override;
    void RegistCallBack(std::function<void(const SecurityCollector::Event &event)> callback);
    int32_t OnNotify(const std::vector<SecurityCollector::Event> &events) override;
    // 清空已注册的回调，并等待本 stub 上所有在途的 OnNotify 执行完毕后返回。
    // 返回后 stub 不会再调用用户回调，此时销毁回调所捕获的状态是安全的。
    // 注意：禁止在用户回调内部（OnNotify 触发的执行流）调用本接口，
    // 否则会因等待自身持有的内部锁而死锁。
    void ClearCallBack();
private:
    // 锁实现（ffrt::mutex）定义在 cpp 中，头文件不暴露 ffrt
    struct CallbackMutex;
    std::function<void(const SecurityCollector::Event &event)> callback_;
    std::unique_ptr<CallbackMutex> mutexes_;
};
}  // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_ACQUIRE_DATA_MANAGER_CALBACK_SERVICE_H