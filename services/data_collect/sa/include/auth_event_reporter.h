/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
#ifndef SECURITY_GUARD_AUTH_EVENT_REPORTER_H
#define SECURITY_GUARD_AUTH_EVENT_REPORTER_H

#include <cstdint>

#include "auth_event.h"

namespace OHOS::Security::SecurityGuard {
// HA 打点适配层（AuthEvent 框架专用）。
// 真实上报走 ha_client_lite_api.h（HA lite 客户端），该头文件依赖尚未进入本仓构建环境，
// 接入点集中在 auth_event_reporter.cpp 的 ReportToHa()，接入时仅需修改该函数，
// 上层打点语义（事件名/字段）不受影响。
class AuthEventReporter {
public:
    // 阻断结果回填打点：SetAuthResult 且 allowFlag=false 时上报。
    // 内容：应用信息（caller pid/uid）+ 事件信息（eventId/content/metadata）。
    static void ReportAuthBlockResult(pid_t callerPid, int32_t callerUid, const AuthEvent &event);

    // 回填超时打点：NotifyAuthEvent 分发后超时未回填时上报。
    // 内容：应用信息（订阅者 pid/uid）+ 事件信息 + 起始时间（分发时刻）+ 结束时间（超时判定时刻），
    // 均为毫秒时间戳，两者之差即超时时长。
    static void ReportAuthResultTimeout(pid_t callerPid, int32_t callerUid, const AuthEvent &event,
        int64_t startMs, int64_t endMs);

    // 当前毫秒时间戳（墙上时钟）
    static int64_t NowMs();

private:
    // HA lite 客户端真实上报的统一接入点。
    // TODO: 引入 ha_client_lite_api.h 后在此组装并上报事件（ eventName + 参数键值对），
    //       当前以 SGLOGI 日志兜底，保证可编译可测。
    static void ReportToHa(const char *eventName, pid_t callerPid, int32_t callerUid, const AuthEvent &event,
        int64_t startMs, int64_t endMs);
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_REPORTER_H

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
