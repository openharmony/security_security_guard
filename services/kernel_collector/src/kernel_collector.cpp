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

#include <system_ability_definition.h>
#include "if_system_ability_manager.h"
#include <mutex>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <thread>
#include "event_define.h"
#include "nlohmann/json.hpp"
#include "i_collector_fwk.h"
#include "kernel_collector.h"
#include "security_guard_log.h"
#include "security_guard_define.h"
#include "securec.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    const int UDK_SMC_MSG_PROC_MAP = 1;
    const int UDK_SMC_MSG_FILE_HASH = 2;
    const int UDK_SMC_MAX_PID_NUM = 5;
    const int UDK_SMC_MAX_FILE_NUM = 5;
    const int UDK_SMC_SUCCESS = 0;
    const int UDK_SMC_MAX_MAP_STORE_LEN = 100;
    const int UDK_SMC_OUT_MAX_LEN = 1024 * 1024;
    const int64_t UDK_SMC_EVENT_ID = 1064001001;
    const std::string UDK_SMC_EVENT_VERSION = "1.0";
}
void FreekcusArg(int type, struct KernelCollectorUdkSmcArg *kcua)
{
    uint32_t i;
    switch (type) {
        case UDK_SMC_MSG_PROC_MAP:
            if (kcua->inputList != nullptr) {
                free(kcua->inputList);
                kcua->inputList = nullptr;
            }
            break;
        case UDK_SMC_MSG_FILE_HASH:
            if (kcua->inputList == nullptr) {
                break;
            }
            for (i = 0; i < kcua->inputNum; i++) {
                struct inputFilePath *fp = static_cast<struct inputFilePath *>(kcua->inputList);
                if (fp[i].path != nullptr) {
                    free(fp[i].path);
                    fp[i].path = nullptr;
                }
            }
            free(kcua->inputList);
            kcua->inputList = nullptr;
            break;
        default:
            break;
    }
    if (kcua->outData != nullptr) {
        free(kcua->outData);
        kcua->outData = nullptr;
    }
}

int ToKernelCollectorUdkSmcHashArg(nlohmann::json input, struct KernelCollectorUdkSmcArg *kcua)
{
    int i = 0;
    int fileTotalLen = 0;
    struct inputFilePath *files = nullptr;
    kcua->inputNum = input["inputMsg"].size();
    if (kcua->inputNum > UDK_SMC_MAX_FILE_NUM) {
        KLOGE("smc input file number too big = %{public}d", kcua->inputNum);
        return FAILED;
    }
    unsigned int fileTotalSize = kcua->inputNum * sizeof(struct inputFilePath);
    if (fileTotalSize > static_cast<unsigned int>(UDK_SMC_OUT_MAX_LEN)) {
        KLOGE("file total len too large limit error");
        return FAILED;
    }
    fileTotalLen = static_cast<int>(fileTotalSize);
    files = static_cast<struct inputFilePath *>(malloc(fileTotalLen));
    if (files == nullptr) {
        KLOGI("smc malloc fail files number = %{public}d", kcua->inputNum);
        return FAILED;
    }
    (void)memset_s(reinterpret_cast<char *>(files), fileTotalLen, 0, fileTotalLen);
    kcua->inputList = files;
    nlohmann::json arrays = input["inputMsg"];
    for (const auto& element:arrays) {
        if (!element.is_string()) {
            KLOGE("input is not string");
            return FAILED;
        }
        std::string file = element.get<std::string>();
        files[i].pathLen = file.size();
        if (files[i].pathLen == 0) {
            KLOGE("input 0 len file path");
            return FAILED;
        }
        files[i].path = static_cast<char *>(malloc(files[i].pathLen));
        if (files[i].path == nullptr) {
            KLOGE("smc kernel collect hash malloc fail i = %{public}d", i);
            return FAILED;
        }
        errno_t rc = memcpy_s(files[i].path, files[i].pathLen,
            static_cast<const char *>(file.c_str()), files[i].pathLen);
        if (rc != EOK) {
            return FAILED;
        }
        KLOGD("smc in path = %{public}s", files[i].path);
        i++;
    }
    return SUCCESS;
}

int ToKernelCollectorUdkSmcMapArg(nlohmann::json input, struct KernelCollectorUdkSmcArg *kcua)
{
    int i = 0;
    int *pids = nullptr;
    kcua->inputNum = input["inputMsg"].size();
    if (kcua->inputNum > UDK_SMC_MAX_PID_NUM || kcua->inputNum == 0) {
        KLOGE("smc input pid number error = %{public}d", kcua->inputNum);
        return FAILED;
    }
    pids = static_cast<int *>(malloc(kcua->inputNum * sizeof(int)));
    if (pids == nullptr) {
        KLOGE("smc malloc fail pid number = %{public}d", kcua->inputNum);
        return FAILED;
    }
    kcua->inputList = pids;
    nlohmann::json arrays = input["inputMsg"];
    for (auto &item : arrays) {
        if (!item.is_number()) {
            KLOGE("smc input error pid number");
            return FAILED;
        }
        pids[i] = item.get<int32_t>();
        if (pids[i] < 0) {
            KLOGE("smc input error pid number %{public}d", pids[i]);
            return FAILED;
        }
        KLOGD("kernel collect pid = %{public}d", pids[i]);
        i++;
    }
    return SUCCESS;
}

int ToKernelCollectorUdkSmcArg(nlohmann::json input, struct KernelCollectorUdkSmcArg *kcua)
{
    int type = input["infoType"];
    int ret = SUCCESS;
    switch (type) {
        case UDK_SMC_MSG_PROC_MAP:
            ret = ToKernelCollectorUdkSmcMapArg(input, kcua);
            break;
        case UDK_SMC_MSG_FILE_HASH:
            ret = ToKernelCollectorUdkSmcHashArg(input, kcua);
            break;
        default:
            KLOGE("smc input error collect type %{public}d", type);
            return FAILED;
    }
    return ret;
}

int ProcPidOutInfo(nlohmann::json &output, char *outData, int outDataMaxLen)
{
    int outLen = *(reinterpret_cast<int *>(outData));
    int readLen = 0;
    int pid = 0;
    int mapsLen = 0;
    int storeMapLen = 0;
    if (outLen < 0 || outLen > outDataMaxLen) {
        KLOGE("smc pid out len=%{public}d error", outLen);
        return FAILED;
    }
    outData = outData + sizeof(int);
    while (readLen < outLen) {
        readLen += sizeof(int);
        if (readLen > outLen) {
            KLOGE("smc read pid readLen =%{public}d error", readLen);
            return FAILED;
        }
        pid = *(reinterpret_cast<int *>(outData + readLen - sizeof(int)));
        readLen += sizeof(int);
        if (readLen > outLen) {
            KLOGE("smc read maps len readLen =%{public}d error", readLen);
            return FAILED;
        }
        mapsLen = *(reinterpret_cast<int *>(outData + readLen - sizeof(int)));
        readLen += mapsLen;
        if (readLen > outLen) {
            KLOGE("smc read maps readLen =%{public}d error", readLen);
            return FAILED;
        }

        char *maps = (outData + readLen - mapsLen);
        std::string mapsStr(maps, mapsLen);
        mapsStr.erase(std::remove(mapsStr.begin(), mapsStr.end(), ' '), mapsStr.end());
        if (mapsStr.size() > static_cast<unsigned long>(UDK_SMC_OUT_MAX_LEN)) {
            KLOGE("map size too large error");
            return FAILED;
        }
        mapsLen = static_cast<int>(mapsStr.size());
        storeMapLen = std::min(mapsLen, UDK_SMC_MAX_MAP_STORE_LEN);
        std::string storeStr = mapsStr.substr(0, storeMapLen);
        KLOGD("smc read pid=%{public}d, masLen = %{public}d, storeMapLen = %{public}zu",
            pid, mapsLen, storeStr.size());
        output["outputMsg"].push_back({pid, storeStr});
    }
    return SUCCESS;
}

std::string HashToStr(char *hash, int hashLen)
{
    int destLen = hashLen * 2 + 1;
    int fixLen = 2;
    char dest[destLen];
    (void)memset_s(dest, destLen, 0, destLen);
    int i;
    int useLen = 0;
    for (i = 0; i < hashLen; i++) {
        if (sprintf_s(dest + useLen, destLen - useLen, "%02x", hash[i]) < 0) {
            return "";
        }
        useLen = useLen + fixLen;
    }
    return std::string(dest);
}

int ProcHashOutInfo(nlohmann::json &output, char *outData, int outDataMaxLen)
{
    int outLen = *(reinterpret_cast<int *>(outData));
    int readLen = 0;
    int filePathLen = 0;
    int hashLen = 0;
    if (outLen < 0 || outLen > outDataMaxLen) {
        KLOGE("smc pid out len=%{public}d error", outLen);
        return FAILED;
    }
    outData = outData + sizeof(int);
    while (readLen < outLen) {
        readLen += sizeof(int);
        if (readLen > outLen) {
            KLOGE("smc read hash readLen =%{public}d error", readLen);
            return FAILED;
        }
        filePathLen = *(reinterpret_cast<int *>(outData + readLen - sizeof(int)));
        readLen += filePathLen;
        if (readLen > outLen) {
            KLOGE("smc read file path len readLen =%{public}d error", readLen);
            return FAILED;
        }
        char *filePath = outData + readLen - filePathLen;
        readLen += sizeof(int);
        if (readLen > outLen) {
            KLOGE("smc read hash len readLen =%{public}d error", readLen);
            return FAILED;
        }
        hashLen = *(reinterpret_cast<int *>(outData + readLen - sizeof(int)));
        readLen += hashLen;
        if (readLen > outLen) {
            KLOGE("smc read hash readLen =%{public}d error", readLen);
            return FAILED;
        }
        char *hash = outData + readLen - hashLen;
        std::string hashStr = HashToStr(hash, hashLen);
        output["outputMsg"].push_back({std::string(filePath, filePathLen), hashStr.c_str()});
        KLOGD("smc read file=%{public}s, hash = %{public}s", filePath, hashStr.c_str());
    }
    return SUCCESS;
}

int ToJson(nlohmann::json &output, char *data, int dataMaxLen, int type)
{
    int ret = 0;
    output["infoType"] = type;
    switch (type) {
        case UDK_SMC_MSG_PROC_MAP:
            ret = ProcPidOutInfo(output, data, dataMaxLen);
            break;
        case UDK_SMC_MSG_FILE_HASH:
            ret = ProcHashOutInfo(output, data, dataMaxLen);
            break;
        default:
            KLOGE("smc kernel collect out error type = %{public}d", type);
            return FAILED;
    }
    return ret;
}

bool InputCheck(nlohmann::json inJson)
{
    if (inJson.is_discarded()) {
        KLOGE("smc input json is discarded");
        return false;
    }
    if (!inJson.contains("infoType") || !inJson.contains("inputMsg")) {
        KLOGE("smc input json need conatains infoType and inputMsg");
        return false;
    }
    if (!inJson.at("infoType").is_number()) {
        KLOGE("smc input json infoType need number");
        return false;
    }
    if (!inJson.at("inputMsg").is_array()) {
        KLOGE("smc input json infoType need number");
        return false;
    }
    return true;
}

int CollectData(std::shared_ptr<SecurityCollector::ICollectorFwk> api, const std::string input)
{
    int ret = SUCCESS;
    nlohmann::json inJson = nlohmann::json::parse(input.c_str(), nullptr, false);
    if (!InputCheck(inJson)) {
        return FAILED;
    }
    struct KernelCollectorUdkSmcArg kc;
    (void)memset_s((char *)&kc, sizeof(struct KernelCollectorUdkSmcArg), 0, sizeof(struct KernelCollectorUdkSmcArg));
    int type = inJson["infoType"].get<int>();
    ret = ToKernelCollectorUdkSmcArg(inJson, &kc);
    if (ret != SUCCESS) {
        FreekcusArg(type, &kc);
        return ret;
    }
    char *out = static_cast<char *>(malloc(UDK_SMC_OUT_MAX_LEN));
    if (out == nullptr) {
        FreekcusArg(type, &kc);
        KLOGE("smc malloc out data failed");
        return FAILED;
    }
    kc.outData = static_cast<void *>(out);
    errno = 0;
    int fd = open("/dev/smc", O_RDONLY);
    if (fd < 0) {
        FreekcusArg(type, &kc);
        KLOGE("smc init devices fail errno = %{public}d", errno);
        return FAILED;
    }
    ret = ioctl(fd, type, &kc);
    if (ret != SUCCESS) {
        FreekcusArg(type, &kc);
        KLOGE("smc proc type %{public}d error res = %{public}d", type, ret);
        return ret;
    }
    nlohmann::json output;
    ret = ToJson(output, static_cast<char *>(kc.outData), UDK_SMC_OUT_MAX_LEN, inJson["infoType"].get<int>());
    if (ret != UDK_SMC_SUCCESS) {
        FreekcusArg(type, &kc);
        KLOGE("smc proc res = %{public}d", ret);
        return ret;
    }
    struct SecurityCollector::Event outEvent = {0};
    outEvent.content = output.dump();
    outEvent.eventId = UDK_SMC_EVENT_ID;
    outEvent.version = UDK_SMC_EVENT_VERSION;
    api->OnNotify(outEvent);
    FreekcusArg(type, &kc);
    close(fd);
    return ret;
}

int KernelCollector::Start(std::shared_ptr<SecurityCollector::ICollectorFwk> api)
{
    if (!api) {
        return FAILED;
    }
    KLOGI("smc proc maps start");
    api_ = api;

    std::string input = api->GetExtraInfo();
    KLOGD("smc parse inJson %{public}s", input.c_str());
    std::thread work([api, input] () {
        CollectData(api, input);
    });
    work.detach();
    KLOGI("smc proc maps end");
    return SUCCESS;
}

int KernelCollector::Stop()
{
    KLOGI("smc kernel collector stop");
    return 0;
}

}  // namespace OHOS::Security::SecurityGuard