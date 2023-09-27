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

#ifndef SECURITY_GUARD_SG_COLLECT_CLIENT_H
#define SECURITY_GUARD_SG_COLLECT_CLIENT_H

#include <mutex>

#include "iremote_object.h"

#include "event_info.h"
#include "i_data_collect_manager.h"
#include "security_guard_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t ReportSecurityInfo(const struct EventInfoSt *info);

#ifdef __cplusplus
}
#endif

namespace OHOS::Security::SecurityGuard {
class NativeDataCollectKit {
public:
    static int32_t ReportSecurityInfo(const std::shared_ptr<EventInfo> &info);
};

class SgCollectClient {
public:
    static SgCollectClient &GetInstance();
    sptr<IDataCollectManager> GetProxy();
    void InitProxy();
    void ReleaseProxy();

private:
    SgCollectClient() = default;
    ~SgCollectClient() = default;
    std::mutex proxyMutex_;
    sptr<IDataCollectManager> proxy_ = nullptr;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ = nullptr;
};

class SgCollectClientDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    SgCollectClientDeathRecipient() = default;
    ~SgCollectClientDeathRecipient() override = default;

    void OnRemoteDied(const wptr<IRemoteObject> &object) override;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_SG_COLLECT_CLIENT_H