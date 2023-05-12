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

#ifndef SECURITY_GUARD_I_DB_LISTENER_H
#define SECURITY_GUARD_I_DB_LISTENER_H

#include "config_define.h"

namespace OHOS::Security::SecurityGuard {
class IDbListener {
public:
    using OptType = enum {
        INSERT,
        DELETE
    };
    virtual ~IDbListener() = default;
    virtual void OnChange(uint32_t optType, const SecEvent &events) = 0;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_I_DB_LISTENER_H
