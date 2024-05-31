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

#ifndef SECURITY_GUARD_ACQUIRE_DATA_SUBSCIBEE_SUBSCRIBE_INFO_H
#define SECURITY_GUARD_ACQUIRE_DATA_SUBSCIBEE_SUBSCRIBE_INFO_H

#include <map>
#include <mutex>
#include <set>

#include "iremote_object.h"

#include "i_db_listener.h"
#include "security_collector_subscribe_info.h"

namespace OHOS::Security::SecurityGuard {
class AcquireDataSubscribeManager {
public:
    static AcquireDataSubscribeManager& GetInstance();
    int InsertSubscribeRecord(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &callback);
    int RemoveSubscribeRecord(const sptr<IRemoteObject> &callback);
    bool Publish(const SecEvent &events);

private:
    AcquireDataSubscribeManager();
    ~AcquireDataSubscribeManager() = default;
    class DbListener : public IDbListener {
    public:
        DbListener() = default;
        ~DbListener() override = default;
        void OnChange(uint32_t optType, const SecEvent &events) override;
    };
    std::shared_ptr<IDbListener> listener_{};
    std::mutex mutex_{};
    std::map<int64_t, std::set<sptr<IRemoteObject>>> eventIdToSubscriberMap_{};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_ACQUIRE_DATA_SUBSCIBEE_SUBSCRIBE_INFO_H