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

#include "variant_value.h"

namespace OHOS {
namespace Security::SecurityGuard {
VariantValue::VariantValue() : type_(ValueType::TYPE_NULL)
{}

VariantValue::~VariantValue()
{}

VariantValue::VariantValue(int32_t value) : type_(ValueType::TYPE_INT)
{
    value_ = value;
}

VariantValue::VariantValue(int64_t value) : type_(ValueType::TYPE_INT64)
{
    value_ = value;
}

VariantValue::VariantValue(const std::string &value) : type_(ValueType::TYPE_STRING)
{
    value_ = value;
}

ValueType VariantValue::GetType() const
{
    return type_;
}

int32_t VariantValue::GetInt() const
{
    if (type_ != ValueType::TYPE_INT) {
        return DEFAULT_VALUE;
    }

    return std::get<int32_t>(value_);
}

int64_t VariantValue::GetInt64() const
{
    if (type_ != ValueType::TYPE_INT64) {
        return DEFAULT_VALUE;
    }

    return std::get<int64_t>(value_);
}

std::string VariantValue::GetString() const
{
    if (type_ != ValueType::TYPE_STRING) {
        return std::string();
    }

    return std::get<std::string>(value_);
}
} // namespace Security::SecurityGuard
} // namespace OHOS
