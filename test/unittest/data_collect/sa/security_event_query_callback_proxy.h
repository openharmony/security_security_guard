/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef SECURITY_GUARD_SECURITY_EVENT_QUERY_CALLBACK_PROXY_H
#define SECURITY_GUARD_SECURITY_EVENT_QUERY_CALLBACK_PROXY_H

#include <string>

#include "iremote_object.h"
#include "iremote_proxy.h"
#include "nocopyable.h"

#include "gmock/gmock.h"

#include "i_data_collect_manager.h"

namespace OHOS::Security::SecurityGuard {
class MockRemoteObject final : public IRemoteObject {
public:
    MockRemoteObject() : IRemoteObject(u"")
    {
    }
    MOCK_METHOD0(GetObjectRefCount, int32_t());
    MOCK_METHOD4(SendRequest, int(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD1(AddDeathRecipient, bool(const sptr<DeathRecipient> &recipient));
    MOCK_METHOD1(RemoveDeathRecipient, bool(const sptr<DeathRecipient> &recipient));
    MOCK_METHOD2(Dump, int(int fd, const std::vector<std::u16string> &args));
};

class SecurityEventQueryCallbackProxy : public IRemoteProxy<ISecurityEventQueryCallback>, public NoCopyable {
public:
    explicit SecurityEventQueryCallbackProxy(const sptr<IRemoteObject> &callback);
    ~SecurityEventQueryCallbackProxy() override = default;
    void OnQuery(const std::vector<SecurityCollector::SecurityEvent> &events) override;
    void OnComplete() override;
    void OnError(const std::string &message) override;

private:
    static inline BrokerDelegator<SecurityEventQueryCallbackProxy> delegator_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_SECURITY_EVENT_QUERY_CALLBACK_PROXY_H
