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

#ifndef SECURITY_COLLECTOR_LOG_H
#define SECURITY_COLLECTOR_LOG_H
#undef LOG_TAG
#define LOG_TAG "S_COLLCTOR"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002F07

#include "hilog/log.h"

namespace OHOS::Security::SecurityCollector {

#ifdef LOGD
#undef LOGD
#endif

#ifdef LOGE
#undef LOGE
#endif

#ifdef LOGF
#undef LOGF
#endif

#ifdef LOGI
#undef LOGI
#endif

#ifdef LOGW
#undef LOGW
#endif

#define LOGD(fmt, ...) \
    (void)HILOG_DEBUG(LOG_CORE, "[%{public}s]" fmt, __func__, ##__VA_ARGS__)
#define LOGE(fmt, ...) \
    (void)HILOG_ERROR(LOG_CORE, "[%{public}s]" fmt, __func__, ##__VA_ARGS__)
#define LOGF(fmt, ...) \
    (void)HILOG_FATAL(LOG_CORE, "[%{public}s]" fmt, __func__, ##__VA_ARGS__)
#define LOGI(fmt, ...) \
    (void)HILOG_INFO(LOG_CORE, "[%{public}s]" fmt, __func__, ##__VA_ARGS__)
#define LOGW(fmt, ...) \
    (void)HILOG_WARN(LOG_CORE, "[%{public}s]" fmt, __func__, ##__VA_ARGS__)
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_COLLECTOR_LOG_H
