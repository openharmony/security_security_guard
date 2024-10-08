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

#ifndef SECURITY_GUARD_PREFERENCES_HELPER_MOCK_H
#define SECURITY_GUARD_PREFERENCES_HELPER_MOCK_H

#include <memory>
#include <mutex>
#include <string>

#include "gmock/gmock.h"

#include "preferences.h"

namespace OHOS::NativePreferences {
struct Options {
public:
    Options(const std::string inputFilePath) : filePath(inputFilePath)
    {
    }

    Options(const char *inputFilePath) : filePath(inputFilePath)
    {
    }

    Options(const std::string &inputFilePath, const std::string &inputbundleName, const std::string &inputdataGroupId)
        : filePath(inputFilePath), bundleName(inputbundleName), dataGroupId(inputdataGroupId)
    {
    }

public:
    std::string filePath{ "" };
    std::string bundleName{ "" };
    std::string dataGroupId{ "" };
};

class PreferenceHelperInterface {
public:
    virtual ~PreferenceHelperInterface() = default;
    virtual std::shared_ptr<Preferences> GetPreferences(const Options &options, int &errCode);
};

class MockPreferenceHelperInterface : public PreferenceHelperInterface {
public:
    MockPreferenceHelperInterface() = default;
    ~MockPreferenceHelperInterface() override = default;
    MOCK_METHOD2(GetPreferences, std::shared_ptr<Preferences>(const Options &options, int &errCode));
};

class PreferencesHelper {
public:
    static std::shared_ptr<Preferences> GetPreferences(const Options &options, int &errCode)
    {
        if (instance_ == nullptr) {
            return nullptr;
        }
        return instance_->GetPreferences(options, errCode);
    };

    static std::shared_ptr<MockPreferenceHelperInterface> GetInterface()
    {
        if (instance_ == nullptr) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (instance_ == nullptr) {
                instance_ = std::make_shared<MockPreferenceHelperInterface>();
            }
        }
        return instance_;
    };

private:
    static std::shared_ptr<MockPreferenceHelperInterface> instance_;
    static std::mutex mutex_;
};
} // namespace OHOS::NativePreferences
#endif // SECURITY_GUARD_PREFERENCES_HELPER_MOCK_H