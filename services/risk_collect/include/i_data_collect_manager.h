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

#ifndef SECURITY_GUARD_I_DATA_COLLECT_MANAGER_H
#define SECURITY_GUARD_I_DATA_COLLECT_MANAGER_H

#include <cstdint>

#include "iremote_broker.h"

namespace OHOS::Security::SecurityGuard {
constexpr int32_t DATA_COLLECT_MANAGER_SA_ID = 3524;

class IDataCollectManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.DataCollectManager");
    enum {
        CMD_DATA_COLLECT = 1,
        CMD_DATA_REQUEST = 2,
    };
};

class IDataCollectManagerCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.DataCollectManager.Callback");
    enum {
        CMD_SET_REQUEST_DATA = 1,
    };
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_I_DATA_COLLECT_MANAGER_H