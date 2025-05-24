/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "json_util.h"
namespace OHOS::Security::SecurityGuard {
namespace JsonUtil {
bool GetNumberInt32(const cJSON *inJson, const std::string &item, int32_t &ret)
{
    if (inJson == nullptr) {
        return false;
    }
    cJSON *keyJson = cJSON_GetObjectItem(inJson, item.c_str());
    if (keyJson == nullptr || !cJSON_IsNumber(keyJson)) {
        return false;
    }
    double tmp = cJSON_GetNumberValue(keyJson);
    if(tmp > INT32_MAX || tmp < INT32_MIN) {
        return false;
    }
    ret = static_cast<int32_t>(tmp);
    return true;
}
bool GetNumberInt64(const cJSON *inJson, const std::string &item, int64_t &ret)
{
    if (inJson == nullptr) {
        return false;
    }
    cJSON *keyJson = cJSON_GetObjectItem(inJson, item.c_str());
    if (keyJson == nullptr || !cJSON_IsNumber(keyJson)) {
        return false;
    }
    ret = static_cast<int64_t>(cJSON_GetNumberValue(keyJson));
    return true;
}

bool GetString(const cJSON *inJson, const std::string &item, std::string &ret)
{
    if(inJson == nullptr) {
        return false;
    }
    cJSON *keyJson = cJSON_GetObjectItem(inJson, item.c_str());
    if (keyJson == nullptr || !cJSON_IsString(keyJson)) {
        return false;
    }
    char *retValue = cJSON_GetStringValue(keyJson);
    if (retValue == nullptr) {
        return false;
    }
    ret = retValue;
    return true;
}

bool GetStringNokey(const cJSON *inJson, std::string &ret)
{
    if (inJson == nullptr) {
        return false;
    }

    if (!cJSON_IsString(inJson)) {
        return false;
    }
    char *retValue = cJSON_GetStringValue(inJson);
    if (retValue == nullptr) {
        return false;
    }
    ret = retValue;
    return true;
}

bool GetBool(const cJSON *inJson, const std::string &item, bool &ret)
{
    if (inJson == nullptr) {
        return false;
    }
    cJSON *keyJson = cJSON_GetObjectItem(inJson, item.c_str());
    if (keyJson == nullptr || !cJSON_IsBool(keyJson)) {
        return false;
    }
    ret = cJSON_IsTrue(keyJson) ? true : false;
    return true;
}

bool AddString(cJSON *outJson, const std::string &item, const std::string &str)
{
    if (outJson == nullptr) {
        return false;
    }
    if (cJSON_AddStringToObject(outJson, item.c_str(), str.c_str()) == nullptr) {
        return false;
    }
    return true;
}

bool AddNumberInt32(cJSON *outJson, const std::string &item, int32_t &num)
{
    if (outJson == nullptr) {
        return false;
    }
    if (cJSON_AddNumberToObject(outJson, item.c_str(), num) == nullptr) {
        return false;
    }
    return true;
}

bool AddNumberInt64(cJSON *outJson, const std::string &item, int64_t &num)
{
    if (outJson == nullptr) {
        return false;
    }
    if (cJSON_AddNumberToObject(outJson, item.c_str(), num) == nullptr) {
        return false;
    }
    return true;
}

bool AddStrArrayInfo(cJSON *object, const std::vector<std::string> &inVector, const char *strKey)
{
    cJSON *strJsonArr = cJSON_CreateArray();
    if (strJsonArr == nullptr) {
        return false;
    }
    for (size_t i = 0; i < inVector.size(); i++) {
        cJSON *item = cJSON_CreateString(inVector[i].c_str());
        if (item == nullptr) {
            cJSON_Delete(strJsonArr);
            return false;
        }
        if (!cJSON_AddItemToArray(strJsonArr, item)) {
            cJSON_Delete(item);
            cJSON_Delete(strJsonArr);
            return false;
        }
    }
    if (!cJSON_AddItemToObject(object, strKey, strJsonArr)) {
        cJSON_Delete(strJsonArr);
        return false;
    }
    return false;
}
}
} // namespace OHOS::Security::SecurityGuard