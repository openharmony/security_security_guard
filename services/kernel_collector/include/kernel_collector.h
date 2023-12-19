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

#ifndef SECURITY_GUARD_KERNEL_COLLECTOR_H
#define SECURITY_GUARD_KERNEL_COLLECTOR_H

#include "i_collector.h"
#include "i_collector_fwk.h"
#include "singleton.h"
#include "hilog/log.h"

namespace OHOS::Security::SecurityGuard {
constexpr OHOS::HiviewDFX::HiLogLabel KLABEL = {
    LOG_CORE,
    0xD002F07,
    "SG_KCOLLECTOR"
};

#define KLOGD(fmt, ...) \
    (void)OHOS::HiviewDFX::HiLog::Debug(KLABEL, "[%{public}s]" fmt, __func__, ##__VA_ARGS__)
#define KLOGE(fmt, ...) \
    (void)OHOS::HiviewDFX::HiLog::Error(KLABEL, "[%{public}s]" fmt, __func__, ##__VA_ARGS__)
#define KLOGF(fmt, ...) \
    (void)OHOS::HiviewDFX::HiLog::Fatal(KLABEL, "[%{public}s]" fmt, __func__, ##__VA_ARGS__)
#define KLOGI(fmt, ...) \
    (void)OHOS::HiviewDFX::HiLog::Info(KLABEL, "[%{public}s]" fmt, __func__, ##__VA_ARGS__)
#define KLOGW(fmt, ...) \
    (void)OHOS::HiviewDFX::HiLog::Warn(KLABEL, "[%{public}s]" fmt, __func__, ##__VA_ARGS__)

struct KernelCollectorUdkSmcArg {
    uint32_t inputNum;
    void *inputList;
    void *outData;
};

struct inputFilePath {
    unsigned int pathLen;    // includes the null terminator
    char *path;
};

class KernelCollector : public SecurityCollector::ICollector, public Singleton<KernelCollector> {
public:
    ~KernelCollector() { Stop(); }
    int Start(std::shared_ptr<SecurityCollector::ICollectorFwk> api) override;
    int Stop() override;

private:
    std::shared_ptr<SecurityCollector::ICollectorFwk> api_{};
};
} // OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_KERNEL_COLLECTOR_H