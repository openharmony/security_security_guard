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

#ifndef ACCESSTOKEN_KIT_H
#define ACCESSTOKEN_KIT_H

#include <string>

#include "gmock/gmock.h"
#include "parcel.h"

namespace OHOS::Security::AccessToken {
typedef unsigned int AccessTokenID;

typedef enum TypeATokenTypeEnum {
    TOKEN_INVALID = -1,
    TOKEN_HAP = 0,
    TOKEN_NATIVE,
    TOKEN_SHELL,
    TOKEN_TYPE_BUTT,
} ATokenTypeEnum;

typedef enum TypePermissionState {
    PERMISSION_DENIED = -1,
    PERMISSION_GRANTED = 0,
} PermissionState;

struct NativeTokenInfoParcel final : public Parcelable {
    NativeTokenInfoParcel() = default;

    ~NativeTokenInfoParcel() override = default;

    bool Marshalling(Parcel &out) const override { return true; };

    static NativeTokenInfoParcel *Unmarshalling(Parcel &in) { return {}; };
};

struct HapTokenInfoParcel final : public Parcelable {
    HapTokenInfoParcel() = default;

    ~HapTokenInfoParcel() override = default;

    bool Marshalling(Parcel &out) const override { return true; };

    static HapTokenInfoParcel *Unmarshalling(Parcel &in) { return {}; };
};

class HapTokenInfo final {
public:
    std::string bundleName;
};

class NativeTokenInfo final {
public:
    std::string processName;
};

class TokenIdKitInterface {
public:
    virtual ~TokenIdKitInterface() = default;
    virtual bool IsSystemAppByFullTokenID(uint64_t tokenId) = 0;
};

class MockTokenIdKitInterface : public TokenIdKitInterface {
public:
    MockTokenIdKitInterface() = default;
    ~MockTokenIdKitInterface() override = default;
    MOCK_METHOD1(IsSystemAppByFullTokenID, bool(uint64_t tokenId));
};

class TokenIdKit {
public:
    static bool IsSystemAppByFullTokenID(uint64_t tokenId)
    {
        if (instance_ == nullptr) {
            return false;
        }
        return instance_->IsSystemAppByFullTokenID(tokenId);
    }

    static std::shared_ptr<MockTokenIdKitInterface> GetInterface()
    {
        if (instance_ == nullptr) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (instance_ == nullptr) {
                instance_ = std::make_shared<MockTokenIdKitInterface>();
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
    static std::shared_ptr<MockTokenIdKitInterface> instance_;
    static std::mutex mutex_;
};

class AccessTokenKitInterface {
public:
    virtual ~AccessTokenKitInterface() = default;
    virtual int32_t VerifyAccessToken(AccessToken::AccessTokenID callerToken, const std::string &permission) = 0;
    virtual ATokenTypeEnum GetTokenType(AccessTokenID tokenID) = 0;
    virtual int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes) = 0;
    virtual int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfoRes) = 0;
};

class MockAccessTokenKitInterface : public AccessTokenKitInterface {
public:
    MockAccessTokenKitInterface() = default;
    ~MockAccessTokenKitInterface() override = default;
    MOCK_METHOD2(VerifyAccessToken, int32_t(AccessToken::AccessTokenID callerToken, const std::string &permission));
    MOCK_METHOD1(GetTokenType, ATokenTypeEnum(AccessTokenID tokenID));
    MOCK_METHOD2(GetHapTokenInfo, int(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes));
    MOCK_METHOD2(GetNativeTokenInfo, int(AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfoRes));
};

class AccessTokenKit {
public:
    static int32_t VerifyAccessToken(AccessToken::AccessTokenID callerToken, const std::string &permission)
    {
        if (instance_ == nullptr) {
            return -1;
        }
        return instance_->VerifyAccessToken(callerToken, permission);
    }

    static ATokenTypeEnum GetTokenType(AccessTokenID tokenID)
    {
        if (instance_ == nullptr) {
            return TOKEN_INVALID;
        }
        return instance_->GetTokenType(tokenID);
    }

    static int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes)
    {
        if (instance_ == nullptr) {
            return -1;
        }
        return instance_->GetHapTokenInfo(tokenID, hapTokenInfoRes);
    }

    static int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfoRes)
    {
        if (instance_ == nullptr) {
            return -1;
        }
        return instance_->GetNativeTokenInfo(tokenID, nativeTokenInfoRes);
    }

    static std::shared_ptr<MockAccessTokenKitInterface> GetInterface()
    {
        if (instance_ == nullptr) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (instance_ == nullptr) {
                instance_ = std::make_shared<MockAccessTokenKitInterface>();
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
    static std::shared_ptr<MockAccessTokenKitInterface> instance_;
    static std::mutex mutex_;
};
}  // OHOS::Security::AccessToken

#endif  // ACCESSTOKEN_KIT_H