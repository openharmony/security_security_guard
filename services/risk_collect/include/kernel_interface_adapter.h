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

#ifndef SECURITY_GUARD_KERNEL_INTERFACE_ADAPTER_H
#define SECURITY_GUARD_KERNEL_INTERFACE_ADAPTER_H

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <linux/netlink.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace OHOS::Security::SecurityGuard {
class KernelInterfaceAdapter {
public:
    KernelInterfaceAdapter() = default;
    virtual ~KernelInterfaceAdapter() = default;
    virtual int Socket(int af, int type, int protocol);
    virtual int Bind(int fd, const struct sockaddr* addr, socklen_t addrLength);
    virtual int Poll(struct pollfd* const fds, nfds_t fdCount, int timeout);
    virtual ssize_t Recv(int socket, void* const buf, size_t len, int flags);
    virtual int Open(const char* const pathName, int flags);
    virtual ssize_t Write(int fd, const void* const buf, size_t count);
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_KERNEL_INTERFACE_ADAPTER_H
