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

#ifndef SECURITY_GUARD_PREFERENCE_WRAPPER_H
#define SECURITY_GUARD_PREFERENCE_WRAPPER_H

#include <mutex>
#include <string>

#include "gmock/gmock.h"

namespace OHOS::Security::SecurityGuard {
class PreferenceWrapperInterface {
public:
    virtual ~PreferenceWrapperInterface() = default;
    virtual int32_t PutInt(const std::string &key, int value) = 0;
    virtual int32_t GetInt(const std::string &key, int defaultValue) = 0;
};

class MockPreferenceWrapperInterface : public PreferenceWrapperInterface {
public:
    MockPreferenceWrapperInterface() = default;
    ~MockPreferenceWrapperInterface() override = default;
    MOCK_METHOD2(PutInt, int32_t(const std::string &key, int value));
    MOCK_METHOD2(GetInt, int32_t(const std::string &key, int defaultValue));
};

class PreferenceWrapper {
public:
    static int32_t PutInt(const std::string &key, int value)
    {
        if (instance_ == nullptr) {
            return -1;
        }
        return instance_->PutInt(key, value);
    }

    static int32_t GetInt(const std::string &key, int defaultValue)
    {
        if (instance_ == nullptr) {
            return -1;
        }
        return instance_->GetInt(key, defaultValue);
    }

    static std::shared_ptr<MockPreferenceWrapperInterface> GetInterface()
    {
        if (instance_ == nullptr) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (instance_ == nullptr) {
                instance_ = std::make_shared<MockPreferenceWrapperInterface>();
            }
        }
        return instance_;
    };

    static void DelInterface()
    {
        if (instance_ != nullptr) {
            instance_.reset();
        }
    };

private:
    static std::shared_ptr<MockPreferenceWrapperInterface> instance_;
    static std::mutex mutex_;
};
}  // OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_PREFERENCE_WRAPPER_H
