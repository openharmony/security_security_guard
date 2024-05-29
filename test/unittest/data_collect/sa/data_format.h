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

#ifndef SECURITY_GUARD_DATA_FORMAT_H
#define SECURITY_GUARD_DATA_FORMAT_H

#include <string>

#include "security_guard_define.h"

namespace OHOS::Security::SecurityGuard {
class DataFormatInterface {
public:
    virtual ~DataFormatInterface() = default;
    virtual bool CheckRiskContent(std::string content) = 0;
    virtual void ParseConditions(std::string conditions, RequestCondition &reqCondition) = 0;
};

class MockDataFormatInterface : public DataFormatInterface {
public:
    MockDataFormatInterface() = default;
    ~MockDataFormatInterface() override = default;
    MOCK_METHOD1(CheckRiskContent, bool(std::string content));
    MOCK_METHOD2(ParseConditions, void(std::string conditions, RequestCondition &reqCondition));
};

class DataFormat {
public:
    static bool CheckRiskContent(std::string content)
    {
        if (instance_ == nullptr) {
            return false;
        }
        return instance_->CheckRiskContent(content);
    }

    static void ParseConditions(std::string conditions, RequestCondition &reqCondition)
    {
        if (instance_ == nullptr) {
            return;
        }
        return instance_->ParseConditions(conditions, reqCondition);
    }

    static std::shared_ptr<MockDataFormatInterface> GetInterface()
    {
        if (instance_ == nullptr) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (instance_ == nullptr) {
                instance_ = std::make_shared<MockDataFormatInterface>();
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
    static std::shared_ptr<MockDataFormatInterface> instance_;
    static std::mutex mutex_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_DATA_FORMAT_H
