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

#include "config_operator.h"

#include "config_define.h"

namespace OHOS::Security::SecurityGuard {
ConfigOperator::ConfigOperator(BaseConfig &config)
    : config_(config) {};

bool ConfigOperator::Init() const
{
    bool success = config_.Load(INIT_MODE);
    if (!success) {
        return false;
    }
    success = config_.Check();
    if (!success) {
        return false;
    }
    return config_.Parse();
}

bool ConfigOperator::Update() const
{
    bool success = config_.Load(UPDATE_MODE);
    if (!success) {
        return false;
    }
    success = config_.Check();
    if (!success) {
        return false;
    }
    return config_.Update();
}
} // OHOS::Security::SecurityGuard