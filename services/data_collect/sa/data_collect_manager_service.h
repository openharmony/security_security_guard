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

#ifndef SECURITY_GUARD_DATA_COLLECT_MANAGER_SERVICE_H
#define SECURITY_GUARD_DATA_COLLECT_MANAGER_SERVICE_H

#include <future>

#include "nocopyable.h"
#include "system_ability.h"

#include "i_db_listener.h"
#include "config_define.h"
#include "data_collect_manager_stub.h"
#include "security_guard_define.h"

namespace OHOS::Security::SecurityGuard {
class DataCollectManagerService : public SystemAbility, public DataCollectManagerStub, public NoCopyable {
DECLARE_SYSTEM_ABILITY(DataCollectManagerService);

public:
    DataCollectManagerService(int32_t saId, bool runOnCreate);
    ~DataCollectManagerService() override = default;
    void OnStart() override;
    void OnStop() override;
    int Dump(int fd, const std::vector<std::u16string>& args) override;
    int32_t RequestDataSubmit(int64_t eventId, std::string &version, std::string &time, std::string &content) override;
    int32_t RequestRiskData(std::string &devId, std::string &eventList, const sptr<IRemoteObject> &callback) override;
    int32_t Subscribe(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &callback) override;
    int32_t Unsubscribe(const sptr<IRemoteObject> &callback) override;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

private:
    class SubscriberDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit SubscriberDeathRecipient(wptr<DataCollectManagerService> service) : service_(service) {}
        ~SubscriberDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override ;
    private:
        wptr<DataCollectManagerService> service_{};
    };
    void DumpEventInfo(int fd, int64_t eventId);
    static std::vector<SecEvent> GetSecEventsFromConditions(RequestCondition &condition);
    static void PushDataCollectTask(const sptr<IRemoteObject> &object, std::string conditions, std::string devId,
        std::shared_ptr<std::promise<int32_t>> promise);
    std::mutex mutex_{};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_{};
};
} // namespace OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_DATA_COLLECT_MANAGER_SERVICE_H