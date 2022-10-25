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

#include "uevent_notify.h"

#include <cerrno>
#include <cstddef>
#include <fcntl.h>
#include <string>
#include <sys/types.h>
#include <unistd.h>

#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    const char* PROC_KERNEL_SG = "/proc/kernel_sg";
    const char* START_SCAN = "0";
    const unsigned long START_SCAN_LEN = static_cast<unsigned long>(strlen(START_SCAN));
    const std::string PREFIX_ADD_WHITELIST = "1";
    const std::string PREFIX_DEL_WHITELIST = "0";
    const std::string SEP = ";";
}

UeventNotify::UeventNotify(KernelInterfaceAdapter &adapter) : adapter_(adapter)
{
}

void UeventNotify::NotifyScan()
{
    int32_t fd = adapter_.Open(PROC_KERNEL_SG, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        SGLOGE("open error, %{public}s", strerror(errno));
        return;
    }

    ssize_t ret = adapter_.Write(fd, START_SCAN, START_SCAN_LEN);
    if (ret != static_cast<ssize_t>(START_SCAN_LEN)) {
        SGLOGE("write error, %{public}s", strerror(errno));
        close(fd);
        return;
    }
    close(fd);
}

void UeventNotify::AddWhiteList(const std::vector<int64_t> &whitelist)
{
    if (whitelist.empty()) {
        SGLOGE("whitelist is empty");
        return;
    }
    int32_t fd = adapter_.Open(PROC_KERNEL_SG, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        SGLOGE("open error, %{public}s", strerror(errno));
        return;
    }

    std::string buf;
    buf += PREFIX_ADD_WHITELIST + SEP + PREFIX_DEL_WHITELIST;
    for (int64_t eventId : whitelist) {
        buf += SEP + std::to_string(eventId);
    }

    ssize_t ret = adapter_.Write(fd, buf.c_str(), buf.length());
    if (ret != static_cast<ssize_t>(buf.length())) {
        SGLOGE("write error, %{public}s", strerror(errno));
        close(fd);
        return;
    }
    close(fd);
}
}
