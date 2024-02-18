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

#include "uevent_listener_impl.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <linux/netlink.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "database_manager.h"
#include "data_format.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "string_ex.h"
#include "task_handler.h"

#include "risk_event_rdb_helper.h"
#include "config_define.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    const char* SG_UEVENT_TAG = "SG_KERNEL_COLLECT_DATA_CMD";
    constexpr int32_t UEVENT_BUF_SIZE = 1024;
}

UeventListenerImpl::UeventListenerImpl(KernelInterfaceAdapter &adapter) : adapter_(adapter)
{
}

UeventListenerImpl::~UeventListenerImpl()
{
    if (ueventFd_ != -1) {
        close(ueventFd_);
        ueventFd_ = -1;
    }
}

bool UeventListenerImpl::InitUevent()
{
    if (ueventFd_ != -1) {
        return false;
    }

    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = static_cast<uint32_t>(getpid()),
        .nl_groups = 0xffffffff
    };

    int32_t fd = adapter_.Socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    if (fd < 0) {
        SGLOGE("fd error");
        return false;
    }

    int32_t ret = adapter_.Bind(fd, reinterpret_cast<const struct sockaddr *>(&addr), sizeof(addr));
    if (ret < 0) {
        SGLOGE("bind error");
        close(fd);
        return false;
    }

    ueventFd_ = fd;
    return (ueventFd_ > 0);
}

int UeventListenerImpl::UeventListen(char *buffer, size_t length)
{
    if (buffer == nullptr || length != UEVENT_BUF_SIZE - 1) {
        SGLOGE("buffer or length error");
        return 0;
    }
    while (true) {
        struct pollfd fds = {
            .fd = ueventFd_,
            .events = POLLIN,
            .revents = 0,
        };
        if ((adapter_.Poll(&fds, 1, -1) > 0) && (fds.revents >= 0) &&
            ((static_cast<uint32_t>(fds.revents) & POLLIN) != 0)) {
            int count = adapter_.Recv(ueventFd_, buffer, length, 0);
            if (count > 0) {
                return count;
            }
        }
        SGLOGE("poll error");
    }

    return 0;
}

ErrorCode UeventListenerImpl::ParseSgEvent(char *buffer, size_t length, SecEvent &eventDataSt)
{
    size_t len = length;
    std::string buf(reinterpret_cast<const char *>(buffer), len);
    auto pos = buf.find_first_of("=");
    if (pos == std::string::npos) {
        SGLOGE("not found separator =");
        return BAD_PARAM;
    }
    len = len - pos;
    buf = buf.substr(pos + 1);
    pos = buf.find_first_of("{");
    if (pos == std::string::npos) {
        SGLOGE("not found separator {");
        return BAD_PARAM;
    }
    len = len - pos;
    eventDataSt.content = buf.substr(pos);
    buf.resize(pos - 1);
    std::vector<std::string> strs;
    SplitStr(buf, "-", strs);
    if (strs.size() != SG_UEVENT_INDEX_CONTENT) {
        SGLOGE("str len error, %{public}u", static_cast<uint32_t>(strs.size()));
        return BAD_PARAM;
    }
    (void)SecurityGuardUtils::StrToI64(strs[SG_UEVENT_INDEX_EVENT_ID], eventDataSt.eventId);
    eventDataSt.version = strs[SG_UEVENT_INDEX_VERSION];
    uint32_t contentLen = 0;
    SecurityGuardUtils::StrToU32(strs[SG_UEVENT_INDEX_CONTENT_LEN], contentLen);
    if (static_cast<uint32_t>(len) < contentLen) {
        SGLOGE("len error, actual len=%{public}u, expect len==%{public}u", static_cast<uint32_t>(len), contentLen);
        return BAD_PARAM;
    }
    eventDataSt.content.resize(contentLen);
    eventDataSt.date = SecurityGuardUtils::GetDate();

    if (!DataFormat::CheckRiskContent(eventDataSt.content)) {
        SGLOGE("check risk content error");
        return JSON_ERR;
    }
    return SUCCESS;
}

void UeventListenerImpl::ParseEvent(char *buffer, size_t length)
{
    if (buffer == nullptr || length > UEVENT_BUF_SIZE) {
        SGLOGE("buffer or length error");
        return;
    }
    char *data = buffer;
    char *end = buffer + length + 1;
    do {
        if (strstr(data, SG_UEVENT_TAG) != nullptr) {
            SecEvent event;
            if (ParseSgEvent(data, length, event) != SUCCESS) {
                return;
            }

            TaskHandler::Task task = [event] () mutable {
                SGLOGD("kernel report eventId=%{public}" PRId64 "", event.eventId);
                (void) DatabaseManager::GetInstance().InsertEvent(KERNEL_SOURCE, event);
            };
            TaskHandler::GetInstance()->AddTask(task);
        }
        data += strlen(data) + 1;
    } while (data < end);
}
}
