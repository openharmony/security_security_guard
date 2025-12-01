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

class TokenIdKit {
public:
    static bool IsSystemAppByFullTokenID(uint64_t tokenId)
    {
        return true;
    }
private:
};


class AccessTokenKit {
public:
    static int32_t VerifyAccessToken(AccessToken::AccessTokenID callerToken, const std::string &permission)
    {
        return PERMISSION_GRANTED;
    }

    static ATokenTypeEnum GetTokenType(AccessTokenID tokenID)
    {
        return TOKEN_HAP;
    }

    static int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes)
    {
        return 0;
    }

    static int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfoRes)
    {
        return 0;
    }

private:
};
}  // OHOS::Security::AccessToken

#endif  // ACCESSTOKEN_KIT_H