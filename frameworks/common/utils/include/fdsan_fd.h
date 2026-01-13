/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef SECURITY_GUARD_FDSAN_FD_H
#define SECURITY_GUARD_FDSAN_FD_H
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include <utility>

struct FdsanFd {
    FdsanFd() = default;

    explicit FdsanFd(int fd)
    {
        Reset(fd);
    }

    FdsanFd(const FdsanFd& copy) = delete;
    FdsanFd(FdsanFd&& move)
    {
        *this = std::move(move);
    }

    ~FdsanFd()
    {
        Reset();
    }

    FdsanFd& operator=(const FdsanFd& copy) = delete;
    FdsanFd& operator=(FdsanFd&& move)
    {
        if (this == &move) {
            return *this;
        }
        Reset();
        if (move.fd_ != -1) {
            fd_ = move.fd_;
            move.fd_ = -1;
            // Acquire ownership from the moved-from object.
            ExchangeTag(fd_, move.Tag(), Tag());
        }
        return *this;
    }

    int Get()
    {
        return fd_;
    }

    void Reset(int new_fd = -1)
    {
        if (fd_ != -1) {
            Close(fd_, Tag());
            fd_ = -1;
        }
        if (new_fd != -1) {
            fd_ = new_fd;
            // Acquire ownership of the presumably unowned fd.
            ExchangeTag(fd_, 0, Tag());
        }
    }

  private:
    int fd_ = -1;

    // Use the address of object as the file tag
    uint64_t Tag()
    {
        return reinterpret_cast<uint64_t>(this);
    }

    static void ExchangeTag(int fd, uint64_t old_tag, uint64_t new_tag)
    {
        if (&fdsan_exchange_owner_tag) {
            fdsan_exchange_owner_tag(fd, old_tag, new_tag);
        }
    }

    static int Close(int fd, uint64_t tag)
    {
        if (&fdsan_close_with_tag) {
            return fdsan_close_with_tag(fd, tag);
        }
    }
};
#endif // SECURITY_GUARD_FDSAN_FD_H