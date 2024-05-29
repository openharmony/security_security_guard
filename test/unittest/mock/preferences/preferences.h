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

#ifndef SECURITY_GUARD_PREFERENCE_MOCK_H
#define SECURITY_GUARD_PREFERENCE_MOCK_H

#include <memory>
#include <mutex>
#include <string>

#include "gmock/gmock.h"

namespace OHOS::NativePreferences {
constexpr int E_ERROR = -1;
constexpr int E_OK = 0;

class PreferencesInterface {
public:
    virtual ~PreferencesInterface() = default;
    virtual int GetInt(const std::string &key, const int &defValue) = 0;
    virtual int PutInt(const std::string &key, int value) = 0;
    virtual void Flush() = 0;
};

class Preferences : public PreferencesInterface {
public:
    Preferences() = default;
    ~Preferences() override = default;
    MOCK_METHOD2(GetInt, int(const std::string &key, const int &defValue));
    MOCK_METHOD2(PutInt, int(const std::string &key, int value));
    MOCK_METHOD0(Flush, void());
};
} // OHOS::NativePreferences
#endif // SECURITY_GUARD_PREFERENCE_MOCK_H