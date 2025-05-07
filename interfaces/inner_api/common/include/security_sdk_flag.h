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

#ifndef SECURITY_COLLECTOR_SDK_FLAG_H
#define SECURITY_COLLECTOR_SDK_FLAG_H

#include <string>
#include <vector>
#include "parcel.h"
#include "event_define.h"

namespace OHOS::Security::SecurityCollector {
class SecuritySdkFlag : public Parcelable {
public:
    SecuritySdkFlag() = default;
    SecuritySdkFlag(const SdkFlags &flag) : flag_(flag) {};
    ~SecuritySdkFlag() override = default;

    SdkFlags GetSdkFlag() const { return flag_; };
    bool Marshalling(Parcel& parcel) const override
    {
        if (!parcel.WriteString(flag_.sdkFlag)) {
            LOGE("failed to write sdkFlag");
            return false;
        }
        if (!parcel.WriteUint32(flag_.instanceFalgs.size())) {
            LOGE("failed to write instanceFalgs size");
            return false;
        }
        for (auto iter : flag_.instanceFalgs) {
            if (!parcel.WriteString(iter)) {
                LOGE("failed to write version");
                return false;
            }
        }
        return true;
    }
    bool ReadFromParcel(Parcel &parcel)
    {
        if (!parcel.ReadString(flag_.sdkFlag)) {
            LOGE("failed to read sdkFlag");
            return false;
        }
        uint32_t size = parcel.ReadUint32();
        if (size > MAX_API_INSTACNE_SIZE) {
            LOGE("the subs size error");
            return false;
        }
        for (uint32_t i = 0; i < size; i++) {
            flag_.instanceFalgs.insert(parcel.ReadString());
        }
        return true;
    }
    static SecuritySdkFlag* Unmarshalling(Parcel& parcel)
    {
        SecuritySdkFlag *flag = new (std::nothrow) SecuritySdkFlag();
        if (flag != nullptr && !flag->ReadFromParcel(parcel)) {
            delete flag;
            flag = nullptr;
        }
        return flag;
    }

private:
    SdkFlags flag_ {};
};
} // namespace OHOS::Security::SecurityCollector

#endif // SECURITY_COLLECTOR_SDK_FLAG_H
