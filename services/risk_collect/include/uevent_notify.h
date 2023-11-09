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

#ifndef SECURITY_GUARD_UEVENT_NOTIFY_H
#define SECURITY_GUARD_UEVENT_NOTIFY_H

#include "kernel_interface_adapter.h"

#include <cstdint>
#include <vector>

namespace OHOS::Security::SecurityGuard {
class UeventNotify {
public:
    explicit UeventNotify(KernelInterfaceAdapter &adapter);
    ~UeventNotify() = default;
    void NotifyScan();
    void AddWhiteList(const std::vector<int64_t> &whitelist);

private:
    KernelInterfaceAdapter &adapter_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_UEVENT_NOTIFY_H
