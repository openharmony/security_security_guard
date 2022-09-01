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

#ifndef SECURITY_GUARD_DATA_MGR_CFG_H
#define SECURITY_GUARD_DATA_MGR_CFG_H

#include <cstdint>

namespace OHOS::Security::SecurityGuard {
class DataMgrCfg {
public:
    static DataMgrCfg& GetInstance();
    void SetDeviceRom(uint32_t deviceRom);
    void SetDeviceRam(uint32_t deviceRam);
    void SetEventMaxRamNum(uint32_t eventMaxRamNum);
    void SetEventMaxRomNum(uint32_t eventMaxRomNum);
    uint32_t GetDeviceRom() const;
    uint32_t GetDeviceRam() const;
    uint32_t GetEventMaxRamNum() const;
    uint32_t GetEventMaxRomNum() const;

private:
    DataMgrCfg() = default;
    uint32_t deviceRom_{};
    uint32_t deviceRam_{};
    uint32_t eventMaxRamNum_{};
    uint32_t eventMaxRomNum_{};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_DATA_MGR_CFG_H
