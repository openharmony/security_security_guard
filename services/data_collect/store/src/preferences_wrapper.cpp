/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "preferences_wrapper.h"

#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_helper.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    const std::string PATH = "/data/service/el1/public/security_guard/securityguardProperties.xml";
}

int32_t PreferenceWrapper::PutInt(const std::string &key, int value)
{
    int32_t errCode = NativePreferences::E_ERROR;
    std::shared_ptr<NativePreferences::Preferences> preferences =
        NativePreferences::PreferencesHelper::GetPreferences(PATH, errCode);
    if (preferences == nullptr || errCode != NativePreferences::E_OK) {
        SGLOGE("get preferences error, code=%{public}d", errCode);
        return errCode;
    }
    errCode = preferences->PutInt(key, value);
    if (errCode != NativePreferences::E_OK) {
        SGLOGE("put int error, code=%{public}d", errCode);
        return errCode;
    }
    preferences->Flush();
    return NativePreferences::E_OK;
}

int32_t PreferenceWrapper::GetInt(const std::string &key, int defaultValue)
{
    int32_t errCode = NativePreferences::E_ERROR;
    std::shared_ptr<NativePreferences::Preferences> preferences =
        NativePreferences::PreferencesHelper::GetPreferences(PATH, errCode);
    if (preferences == nullptr || errCode != NativePreferences::E_OK) {
        SGLOGE("get preferences error, code=%{public}d", errCode);
        return -1;
    }
    return preferences->GetInt(key, defaultValue);
}
}