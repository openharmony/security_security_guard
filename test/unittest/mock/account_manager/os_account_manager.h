/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef SECURITY_GUARD_OS_ACCOUNT_MANAGER_MOCK_H
#define SECURITY_GUARD_OS_ACCOUNT_MANAGER_MOCK_H

#include <memory>
#include <mutex>

#include "errors.h"

#include "gmock/gmock.h"

namespace OHOS::AccountSA {
class OsAccountSubscriber {
public:
    virtual ~OsAccountSubscriber() = default;
    virtual void OnAccountsChanged(const int &id) = 0;
};

class OsAccountManagerInterface {
public:
    virtual ~OsAccountManagerInterface() = default;
    virtual ErrCode QueryActiveOsAccountIds(std::vector<int32_t>& ids) = 0;
};

class MockOsAccountManagerInterface : public OsAccountManagerInterface {
public:
    MockOsAccountManagerInterface() = default;
    ~MockOsAccountManagerInterface() override = default;
    MOCK_METHOD1(QueryActiveOsAccountIds, ErrCode(std::vector<int32_t>& ids));
    MOCK_METHOD1(SubscribeOsAccount, ErrCode(const std::shared_ptr<OsAccountSubscriber> &subscriber));
    MOCK_METHOD1(UnsubscribeOsAccount, ErrCode(const std::shared_ptr<OsAccountSubscriber> &subscriber));
};

class OsAccountManager {
public:
    static ErrCode SubscribeOsAccount(const std::shared_ptr<OsAccountSubscriber> &subscriber)
    {
        if (instance_ == nullptr) {
            return -1;
        }
        return instance_->SubscribeOsAccount(subscriber);
    };

    static ErrCode UnsubscribeOsAccount(const std::shared_ptr<OsAccountSubscriber> &subscriber)
    {
        if (instance_ == nullptr) {
            return -1;
        }
        return instance_->UnsubscribeOsAccount(subscriber);
    };

    static ErrCode QueryActiveOsAccountIds(std::vector<int32_t>& ids)
    {
        if (instance_ == nullptr) {
            return -1;
        }
        return instance_->QueryActiveOsAccountIds(ids);
    };

    static std::shared_ptr<MockOsAccountManagerInterface> GetInterface()
    {
        if (instance_ == nullptr) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (instance_ == nullptr) {
                instance_ = std::make_shared<MockOsAccountManagerInterface>();
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
    static std::shared_ptr<MockOsAccountManagerInterface> instance_;
    static std::mutex mutex_;
};
} // OHOS::AccountSA
#endif // SECURITY_GUARD_OS_ACCOUNT_MANAGER_MOCK_H