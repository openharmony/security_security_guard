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

#include "kernel_interface_adapter.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <fcntl.h>
#include <linux/netlink.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

namespace OHOS::Security::SecurityGuard {
namespace  {
    constexpr int INVALID_VALUE = -1;
    const char* PROC_KERNEL_SG = "/proc/kernel_sg";
}

int KernelInterfaceAdapter::Socket(int af, int type, int protocol)
{
    return socket(af, type, protocol);
}

int KernelInterfaceAdapter::Bind(int fd, const struct sockaddr* addr, socklen_t addrLength)
{
    if (addr == nullptr) {
        return INVALID_VALUE;
    }
    return bind(fd, addr, addrLength);
}

int KernelInterfaceAdapter::Poll(struct pollfd* const fds, nfds_t fdCount, int timeout)
{
    if (fds == nullptr) {
        return 0;
    }
    return poll(fds, fdCount, timeout);
}

ssize_t KernelInterfaceAdapter::Recv(int socket, void* const buf, size_t len, int flags)
{
    if (buf == nullptr) {
        return 0;
    }
    return recv(socket, buf, len, flags);
}

int KernelInterfaceAdapter::Open(const char* const pathName, int flags)
{
    if (strcmp(pathName, PROC_KERNEL_SG) != 0) {
        return INVALID_VALUE;
    }
    return open(pathName, flags);
}

ssize_t KernelInterfaceAdapter::Write(int fd, const void* const buf, size_t count)
{
    if (buf == nullptr) {
        return 0;
    }
    return write(fd, buf, count);
}
}
