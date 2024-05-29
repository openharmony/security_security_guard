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

#ifndef SECURITY_GUARD_REAL_TIME_DETECT_STUB_H
#define SECURITY_GUARD_REAL_TIME_DETECT_STUB_H

#include "iremote_stub.h"
#include "i_real_time_detect_manager.h"

namespace OHOS::Security::SecurityGuard {
class RealTimeDetectStub : public IRemoteStub<IRealTimeDetectManager> {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.RealTimeDetectStub");
    RealTimeDetectStub() = default;
    ~RealTimeDetectStub() override = default;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_REAL_TIME_DETECT_STUB_H
