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

#include "uevent_listener.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <linux/netlink.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "securec.h"

#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int32_t UEVENT_BUF_SIZE = 1024;
}

UeventListener::UeventListener(UeventListenerImpl &impl) : impl_(impl)
{
}

void UeventListener::Start()
{
    if (!impl_.InitUevent()) {
        SGLOGE("InitUevent failed");
        return;
    }

    char buffer[UEVENT_BUF_SIZE] = { 0 };
    while (true) {
        (void)memset_s(buffer, UEVENT_BUF_SIZE, 0, UEVENT_BUF_SIZE);
        int length = impl_.UeventListen(buffer, sizeof(buffer) - 1);
        if (length <= 0 || length >= UEVENT_BUF_SIZE) {
            SGLOGE("length error, length=%{public}d", length);
            continue;
        }
        buffer[length] = '\0';
        impl_.ParseEvent(buffer, length);
    }
}
}
