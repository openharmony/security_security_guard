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

#ifndef SECURITY_CONFIG_UPDATE_H
#define SECURITY_CONFIG_UPDATE_H

#include <string>

#include "parcel.h"

namespace OHOS::Security::SecurityGuard {
class SecurityConfigUpdateInfo : public Parcelable {
public:
    SecurityConfigUpdateInfo() = default;
    SecurityConfigUpdateInfo(int32_t fd, const std::string &name = "") : fd_(fd), fileName_(name) {};
    ~SecurityConfigUpdateInfo() override = default;
    bool Marshalling(Parcel& parcel) const override
    {
        if (!parcel.WriteInt32(fd_)) {
            return false;
        }
        if (!parcel.WriteString(fileName_)) {
            return false;
        }
        return true;
    }
    bool ReadFromParcel(Parcel &parcel)
    {
        if (!parcel.ReadInt32(fd_)) {
            return false;
        }
        if (!parcel.ReadString(fileName_)) {
            return false;
        }
        return true;
    }
    static SecurityConfigUpdateInfo* Unmarshalling(Parcel& parcel)
    {
        SecurityConfigUpdateInfo *info = new (std::nothrow) SecurityConfigUpdateInfo();
        if (info != nullptr && !info->ReadFromParcel(parcel)) {
            delete info;
            info = nullptr;
        }
        return info;
    }
    int32_t GetFd() const { return fd_; };
    std::string GetFileName() const { return fileName_; };
private:
    int32_t fd_{};
    std::string fileName_{};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_CONFIG_UPDATE_H