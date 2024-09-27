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

#ifndef SECURITY_EVENT_CONFIG_H
#define SECURITY_EVENT_CONFIG_H

#include <string>
#include <vector>
#include "parcel.h"
#include "security_event_info.h"

namespace OHOS::Security::SecurityGuard {
class SecurityEventConfig : public Parcelable {
public:
    SecurityEventConfig() = default;
    SecurityEventConfig(const EventCfg &config) : config_(config){};
    ~SecurityEventConfig() override = default;

    EventCfg GetEventConfig() const
    {
        return config_;
    };

    bool Marshalling(Parcel &parcel) const override
    {
        if (!parcel.WriteInt64(config_.eventId)) {
            return false;
        }
        if (!parcel.WriteString(config_.eventName)) {
            return false;
        }
        if (!parcel.WriteUint32(config_.version)) {
            return false;
        }
        if (!parcel.WriteUint32(config_.eventType)) {
            return false;
        }
        if (!parcel.WriteUint32(config_.collectOnStart)) {
            return false;
        }
        if (!parcel.WriteUint32(config_.dataSensitivityLevel)) {
            return false;
        }
        if (!parcel.WriteUint32(config_.storageRamNums)) {
            return false;
        }
        if (!parcel.WriteInt32(config_.storageRomNums)) {
            return false;
        }

        if (!parcel.WriteUint32(config_.storageTime)) {
            return false;
        }

        uint32_t ownerSize = config_.owner.size();
        if (!parcel.WriteUint32(ownerSize)) {
            return false;
        }

        for (uint32_t index = 0; index < ownerSize; index++) {
            if (!parcel.WriteString(config_.owner[index])) {
                return false;
            }
        }
        if (!parcel.WriteUint32(config_.source)) {
            return false;
        }

        if (!parcel.WriteString(config_.dbTable)) {
            return false;
        }
        if (!parcel.WriteString(config_.prog)) {
            return false;
        }
        return true;
    };

    bool ReadFromParcel(Parcel &parcel)
    {
        if (!parcel.ReadInt64(config_.eventId)) {
            return false;
        }
        if (!parcel.ReadString(config_.eventName)) {
            return false;
        }
        if (!parcel.ReadUint32(config_.version)) {
            return false;
        }
        if (!parcel.ReadUint32(config_.eventType)) {
            return false;
        }
        if (!parcel.ReadUint32(config_.collectOnStart)) {
            return false;
        }
        if (!parcel.ReadUint32(config_.dataSensitivityLevel)) {
            return false;
        }
        if (!parcel.ReadUint32(config_.storageRamNums)) {
            return false;
        }
        if (!parcel.ReadUint32(config_.storageRomNums)) {
            return false;
        }

        if (!parcel.ReadInt32(config_.storageTime)) {
            return false;
        }

        uint32_t ownerSize = 0;
        if (!parcel.ReadUint32(ownerSize)) {
            return false;
        }

        for (uint32_t index = 0; index < ownerSize; index++) {
            if (!parcel.ReadString(config_.owner[index])) {
                return false;
            }
        }

        if (!parcel.ReadUint32(config_.source)) {
            return false;
        }

        if (!parcel.ReadString(config_.dbTable)) {
            return false;
        }
        if (!parcel.ReadString(config_.prog)) {
            return false;
        }
        return true;
    };

    static SecurityEventConfig *Unmarshalling(Parcel &parcel)
    {
        SecurityEventConfig *config = new (std::nothrow) SecurityEventConfig();
        if (config != nullptr && !config->ReadFromParcel(parcel)) {
            delete config;
            config = nullptr;
        }

        return config;
    };

private:
    EventCfg config_{};
};

}  // namespace OHOS::Security::SecurityGuard

#endif  // SECURITY_EVENT_CONFIG_H
