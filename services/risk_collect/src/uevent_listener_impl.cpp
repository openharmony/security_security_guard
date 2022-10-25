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

#include "data_format.h"
#include "data_manager_wrapper.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "task_handler.h"

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

ErrorCode UeventListenerImpl::ParseSgEvent(char *buffer, size_t length, EventDataSt &eventDataSt)
{
    char *savePoint = nullptr;
    char *subString = strtok_r(buffer, "=", &savePoint);

    uint32_t contentLen;
    int index = 0;
    eventDataSt.date = SecurityGuardUtils::GetData();
    subString = strtok_r(nullptr, "-", &savePoint);
    while (subString != nullptr) {
        switch (index) {
            case SG_UEVENT_INDEX_EVENT_ID:
                eventDataSt.eventId = static_cast<int64_t>(atoi(subString));
                SGLOGI("eventId=%{public}ld", eventDataSt.eventId);
                break;
            case SG_UEVENT_INDEX_VERSION:
                eventDataSt.version = std::string(subString);
                SGLOGI("version=%{public}s", eventDataSt.version.c_str());
                break;
            case SG_UEVENT_INDEX_CONTENT_LEN:
                contentLen = static_cast<uint32_t>(atoi(subString));
                SGLOGI("content length=%{public}u", contentLen);
                break;
            case SG_UEVENT_INDEX_CONTENT:
                eventDataSt.content = std::string(subString);
                if (static_cast<uint32_t>(eventDataSt.content.length()) + 1 != contentLen) {
                    SGLOGE("content len=%{public}u", static_cast<uint32_t>(eventDataSt.content.length()));
                    return BAD_PARAM;
                }
                break;
            default:
                SGLOGE("SG_UEVENT error");
                return BAD_PARAM;
        }
        subString = strtok_r(nullptr, "-", &savePoint);
        index++;
    }

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
            EventDataSt eventDataSt;
            if (ParseSgEvent(data, length, eventDataSt) != SUCCESS) {
                return;
            }

            TaskHandler::Task task = [eventDataSt] {
                ErrorCode code = DataManagerWrapper::GetInstance().AddCollectInfo(eventDataSt);
                SGLOGI("kernel AddCollectInfo eventId %{public}ld code is %{public}d", eventDataSt.eventId, code);
            };
            TaskHandler::GetInstance()->AddTask(task);
        }
        data += strlen(data) + 1;
    } while (data < end);
}
}
