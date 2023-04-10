/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SECURITY_GUARD_CONFIG_MANAGER_H
#define SECURITY_GUARD_CONFIG_MANAGER_H

#include "singleton.h"

#include "event_config.h"
#include "config_operator.h"
#include "model_config.h"

namespace OHOS::Security::SecurityGuard {
class ConfigManager : public DelayedSingleton<ConfigManager> {
public:
    void StartUpdate();

    template<typename T>
    static bool InitConfig()
    {
        T config;
        auto cfgOperator = std::make_unique<ConfigOperator>(config);
        return cfgOperator->Init();
    }

    template<typename T>
    static bool UpdataConfig()
    {
        T config;
        auto cfgOperator = std::make_unique<ConfigOperator>(config);
        return cfgOperator->Update();
    }
};
} // OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_CONFIG_MANAGER_H