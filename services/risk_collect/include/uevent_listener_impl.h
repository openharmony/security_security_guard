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

#ifndef SECURITY_GUARD_UEVENT_LISTENER_IMPL_H
#define SECURITY_GUARD_UEVENT_LISTENER_IMPL_H

#include "kernel_interface_adapter.h"
#include "model_cfg_marshalling.h"
#include "security_guard_define.h"

namespace OHOS::Security::SecurityGuard {
using SgUeventFiled = enum {
    SG_UEVENT_INDEX_EVENT_ID,
    SG_UEVENT_INDEX_VERSION,
    SG_UEVENT_INDEX_CONTENT_LEN,
    SG_UEVENT_INDEX_CONTENT,
};

class UeventListenerImpl {
public:
    explicit UeventListenerImpl(KernelInterfaceAdapter &adapter);
    virtual ~UeventListenerImpl();
    virtual bool InitUevent();
    virtual int UeventListen(char *buffer, size_t length);
    virtual void ParseEvent(char *buffer, size_t length);

private:
    ErrorCode ParseSgEvent(char *buffer, size_t length, SecEvent &eventDataSt);
    int ueventFd_{-1};
    KernelInterfaceAdapter &adapter_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_UEVENT_LISTENER_IMPL_H
