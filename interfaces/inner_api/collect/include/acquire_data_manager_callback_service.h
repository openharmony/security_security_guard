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
#include <mutex>
#include "acquire_data_manager_callback_stub.h"
#include "i_collector_subscriber.h"

namespace OHOS::Security::SecurityGuard {
class AcquireDataManagerCallbackService : public AcquireDataManagerCallbackStub {
public:
    explicit AcquireDataManagerCallbackService() = default;
    ~AcquireDataManagerCallbackService() override = default;
    void RegistCallBack(std::function<void(const SecurityCollector::Event &event)> callback);
    int32_t OnNotify(const std::vector<SecurityCollector::Event> &events) override;
    // 清空已注册的回调，并等待所有在途的OnNotify执行完毕后返回。
    // 返回后 stub不会再调用用户回调，此时销毁回调所捕获的状态时安全的。
    void ClearCallback();
private:
    std::function<void(const SecurityCollector::Event &event)> callback_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_ACQUIRE_DATA_MANAGER_CALBACK_SERVICE_H