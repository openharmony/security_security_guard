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

#ifndef SECURITY_GUARD_DATA_DISTRIBUTE_TASK_H
#define SECURITY_GUARD_DATA_DISTRIBUTE_TASK_H

#include <string>

#include "iremote_object.h"

#include "base_task.h"
#include "security_guard_define.h"

namespace OHOS::Security::SecurityGuard {
class DataDistributeTask final : public BaseTask {
public:
    DataDistributeTask(std::string &devId, std::string &eventList, sptr<IRemoteObject> &obj);
    void OnExecute() override;

private:
    static ErrorCode ParseEventList(std::string &eventList, std::vector<int64_t> &eventListVec);
    std::string devId_;
    std::string eventList_;
    sptr<IRemoteObject> obj_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_DATA_DISTRIBUTE_TASK_H
