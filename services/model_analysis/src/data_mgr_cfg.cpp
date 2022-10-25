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

#include "data_mgr_cfg.h"

namespace OHOS::Security::SecurityGuard {
DataMgrCfg &DataMgrCfg::GetInstance()
{
    static DataMgrCfg instance;
    return instance;
}

void DataMgrCfg::SetDeviceRom(uint32_t deviceRom)
{
    deviceRom_ = deviceRom;
}

void DataMgrCfg::SetDeviceRam(uint32_t deviceRam)
{
    deviceRam_ = deviceRam;
}

void DataMgrCfg::SetEventMaxRamNum(uint32_t eventMaxRamNum)
{
    eventMaxRamNum_ = eventMaxRamNum;
}

void DataMgrCfg::SetEventMaxRomNum(uint32_t eventMaxRomNum)
{
    eventMaxRomNum_ = eventMaxRomNum;
}

uint32_t DataMgrCfg::GetDeviceRom() const
{
    return deviceRom_;
}

uint32_t DataMgrCfg::GetDeviceRam() const
{
    return deviceRam_;
}

uint32_t DataMgrCfg::GetEventMaxRamNum() const
{
    return eventMaxRamNum_;
}

uint32_t DataMgrCfg::GetEventMaxRomNum() const
{
    return eventMaxRomNum_;
}
}