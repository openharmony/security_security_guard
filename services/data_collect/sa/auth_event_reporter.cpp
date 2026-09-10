/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "auth_event_reporter.h"

#include <cinttypes>
#include <string>

#include "security_guard_log.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
namespace OHOS::Security::SecurityGuard {
namespace {
    // HA 事件名（接入 ha_client_lite_api.h 时沿用）
    constexpr const char* AUTH_BLOCK_RESULT_EVENT = "AUTH_BLOCK_RESULT";
}

void AuthEventReporter::ReportAuthBlockResult(pid_t callerPid, int32_t callerUid, const AuthEvent &event)
{
    ReportToHa(AUTH_BLOCK_RESULT_EVENT, callerPid, callerUid, event);
}

void AuthEventReporter::ReportToHa(const char *eventName, pid_t callerPid, int32_t callerUid,
    const AuthEvent &event)
{
    // TODO: 接入 HA lite 客户端真实上报。
    // 步骤：#include "ha_client_lite_api.h"（依赖部件引入本仓构建后），
    //       按 eventName 上报事件，参数：CALLER_PID/CALLER_UID/EVENT_ID/CONTENT/METADATA。
    // 注意：HA 上报若为耗时接口，仅允许锁外调用（与 Notify 推送同纪律）。
    const std::string content = event.GetContent();
    const std::string metadata = event.GetMetadata();
    SGLOGI("ha report, event=%{public}s, pid=%{public}d, uid=%{public}d, eventId=%{public}" PRId64,
        eventName, static_cast<int32_t>(callerPid), callerUid, event.GetEventId());
    SGLOGD("ha report detail, content=%{public}s, metadata=%{public}s", content.c_str(), metadata.c_str());
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
