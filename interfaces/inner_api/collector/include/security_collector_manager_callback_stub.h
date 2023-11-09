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

#ifndef SECURITY_GUARD_SECURITY_COLLECTOR_MANAGER_CALBACK_STUB_H
#define SECURITY_GUARD_SECURITY_COLLECTOR_MANAGER_CALBACK_STUB_H

#include "i_security_collector_manager.h"
#include "iremote_stub.h"

namespace OHOS::Security::SecurityCollector {
class SecurityCollectorManagerCallbackStub : public IRemoteStub<ISecurityCollectorManagerCallback>, public NoCopyable {
public:
    SecurityCollectorManagerCallbackStub() = default;
    ~SecurityCollectorManagerCallbackStub() override = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
};
} // namespace OHOS::Security::SecurityCollector

#endif // SECURITY_GUARD_SECURITY_COLLECTOR_MANAGER_CALBACK_STUB_H