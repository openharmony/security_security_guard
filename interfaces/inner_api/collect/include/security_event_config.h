/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

    bool WriteInt64ToParcel(Parcel &parcel, int64_t value) const
    {
        return parcel.WriteInt64(value);
    }

    bool WriteUint32ToParcel(Parcel &parcel, uint32_t value) const
    {
        return parcel.WriteUint32(value);
    }

    bool WriteInt32ToParcel(Parcel &parcel, int32_t value) const
    {
        return parcel.WriteInt32(value);
    }

    bool WriteStringToParcel(Parcel &parcel, const std::string &value) const
    {
        return parcel.WriteString(value);
    }

    bool WriteStringArrayToParcel(Parcel &parcel, const std::vector<std::string> &array) const
    {
        uint32_t size = array.size();
        if (!WriteUint32ToParcel(parcel, size)) {
            return false;
        }
        for (const auto &str : array) {
            if (!WriteStringToParcel(parcel, str)) {
                return false;
            }
        }
        return true;
    }

    bool ReadInt64FromParcel(Parcel &parcel, int64_t &value) const
    {
        return parcel.ReadInt64(value);
    }

    bool ReadUint32FromParcel(Parcel &parcel, uint32_t &value) const
    {
        return parcel.ReadUint32(value);
    }

    bool ReadInt32FromParcel(Parcel &parcel, int32_t &value) const
    {
        return parcel.ReadInt32(value);
    }

    bool ReadStringFromParcel(Parcel &parcel, std::string &value) const
    {
        return parcel.ReadString(value);
    }

    bool ReadStringArrayFromParcel(Parcel &parcel, std::vector<std::string> &array) const
    {
        uint32_t size = 0;
        if (!ReadUint32FromParcel(parcel, size)) {
            return false;
        }
        for (uint32_t i = 0; i < size; i++) {
            std::string str;
            if (!ReadStringFromParcel(parcel, str)) {
                return false;
            }
            array.push_back(str);
        }
        return true;
    }

    bool Marshalling(Parcel &parcel) const override
    {
        return WriteInt64ToParcel(parcel, config_.eventId) &&
            WriteStringToParcel(parcel, config_.eventName) &&
            WriteUint32ToParcel(parcel, config_.version) &&
            WriteUint32ToParcel(parcel, config_.eventType) &&
            WriteUint32ToParcel(parcel, config_.collectOnStart) &&
            WriteUint32ToParcel(parcel, config_.dataSensitivityLevel) &&
            WriteUint32ToParcel(parcel, config_.discardEventWhiteList) &&
            WriteUint32ToParcel(parcel, config_.storageRamNums) &&
            WriteInt32ToParcel(parcel, config_.storageRomNums) &&
            WriteUint32ToParcel(parcel, config_.storageTime) &&
            WriteStringArrayToParcel(parcel, config_.owner) &&
            WriteUint32ToParcel(parcel, config_.source) &&
            WriteStringToParcel(parcel, config_.dbTable) &&
            WriteStringToParcel(parcel, config_.prog) &&
            WriteUint32ToParcel(parcel, config_.isBatchUpload);
    }

    bool ReadFromParcel(Parcel &parcel)
    {
        return ReadInt64FromParcel(parcel, config_.eventId) &&
            ReadStringFromParcel(parcel, config_.eventName) &&
            ReadUint32FromParcel(parcel, config_.version) &&
            ReadUint32FromParcel(parcel, config_.eventType) &&
            ReadUint32FromParcel(parcel, config_.collectOnStart) &&
            ReadUint32FromParcel(parcel, config_.dataSensitivityLevel) &&
            ReadUint32FromParcel(parcel, config_.discardEventWhiteList) &&
            ReadUint32FromParcel(parcel, config_.storageRamNums) &&
            ReadUint32FromParcel(parcel, config_.storageRomNums) &&
            ReadInt32FromParcel(parcel, config_.storageTime) &&
            ReadStringArrayFromParcel(parcel, config_.owner) &&
            ReadUint32FromParcel(parcel, config_.source) &&
            ReadStringFromParcel(parcel, config_.dbTable) &&
            ReadStringFromParcel(parcel, config_.prog) &&
            ReadUint32FromParcel(parcel, config_.isBatchUpload);
    }

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
