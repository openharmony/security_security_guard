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

#include "data_format.h"
#include "data_manager_wrapper.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "task_handler.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int32_t UEVENT_BUF_SIZE = 1024;
    const char* SG_UEVENT_TAG = "SG_KERNEL_COLLECT_DATA_CMD";
}

UeventListener::~UeventListener()
{
    if (ueventFd_ != -1) {
        close(ueventFd_);
        ueventFd_ = -1;
    }
}

bool UeventListener::InitUevent()
{
    if (ueventFd_ != -1) {
        return false;
    }

    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = static_cast<uint32_t>(getpid()),
        .nl_groups = 0xffffffff
    };

    int32_t fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    if (fd < 0) {
        SGLOGE("fd error");
        return false;
    }

    int32_t ret = bind(fd, reinterpret_cast<const struct sockaddr *>(&addr), sizeof(addr));
    if (ret < 0) {
        SGLOGE("bind error");
        close(fd);
        return false;
    }

    ueventFd_ = fd;
    return (ueventFd_ > 0);
}

int UeventListener::UeventListen(char *buffer, size_t length) const
{
    while (true) {
        struct pollfd fds = {
            .fd = ueventFd_,
            .events = POLLIN,
            .revents = 0,
        };
        if ((poll(&fds, 1, -1) > 0) && (fds.revents >= 0) && ((static_cast<uint32_t>(fds.revents) & POLLIN) != 0)) {
            int count = recv(ueventFd_, buffer, length, 0);
            if (count > 0) {
                return count;
            }
        }
        SGLOGE("poll error");
    }

    return 0;
}

ErrorCode UeventListener::ParseSgEvent(char *buffer, size_t length, EventDataSt &eventDataSt)
{
    char *savePoint = nullptr;
    if (strtok_r(buffer, "=", &savePoint) == nullptr) {
        SGLOGE("strtok_r error");
        return BAD_PARAM;
    }

    uint32_t contentLen;
    int index = 0;
    eventDataSt.date = SecurityGuardUtils::GetData();
    char *subString = strtok_r(nullptr, "-", &savePoint);
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

void UeventListener::ParseEvent(char *buffer, size_t length)
{
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
                SGLOGI("AddCollectInfo code is %{public}d", code);
            };
            TaskHandler::GetInstance()->AddTask(task);
        }
        data += strlen(data) + 1;
    } while (data < end);
}

void UeventListener::Start()
{
    if (!InitUevent()) {
        SGLOGE("InitUevent failed");
        return;
    }

    char buffer[UEVENT_BUF_SIZE] = { 0 };
    while (true) {
        (void)memset_s(buffer, UEVENT_BUF_SIZE, 0, UEVENT_BUF_SIZE);
        int length = UeventListen(buffer, sizeof(buffer) - 1);
        if (length <= 0) {
            SGLOGE("length error");
            continue;
        }
        buffer[length] = '\0';
        ParseEvent(buffer, length);
    }
}
}
