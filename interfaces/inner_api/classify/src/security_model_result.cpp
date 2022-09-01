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

#include "security_model_result.h"

namespace OHOS::Security::SecurityGuard {
std::string SecurityModelResult::GetDevId() const
{
    return devId_;
}

uint32_t SecurityModelResult::GetModelId() const
{
    return modelId_;
}

std::string SecurityModelResult::GetResult() const
{
    return result_;
}
}