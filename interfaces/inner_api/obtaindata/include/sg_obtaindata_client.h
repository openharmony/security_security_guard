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

#ifndef SECURITY_GUARD_SG_OBTAINDATA_CLIENT_H
#define SECURITY_GUARD_SG_OBTAINDATA_CLIENT_H

#include <functional>
#include <memory>
#include <string>

#include "obtaindata_callback.h"

namespace OHOS::Security::SecurityGuard {
class ObtainDataKit {
public:
    static int32_t RequestSecurityEventInfoAsync(std::string &devId, std::string &eventList,
        std::shared_ptr<RequestSecurityEventInfoCallback> &callback);

private:
    static int32_t RequestSecurityEventInfo(std::string &devId, std::string &eventList,
        std::function<int32_t(std::string &, std::string &, uint32_t)> callback);
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_SG_OBTAINDATA_CLIENT_H