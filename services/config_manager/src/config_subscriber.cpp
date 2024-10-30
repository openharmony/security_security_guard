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

#include "config_subscriber.h"

#include <fstream>
#include <mutex>

#include "directory_ex.h"
#include "string_ex.h"

#include "bigdata.h"
#include "event_config.h"
#include "config_define.h"
#include "config_manager.h"
#include "model_config.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "i_model_info.h"

namespace OHOS::Security::SecurityGuard {

bool ConfigSubscriber::UpdateConfig(const std::string &file)
{
    ConfigUpdateEvent event{};
    bool isSuccess = false;
    if (file == CONFIG_CACHE_FILES[EVENT_CFG_INDEX]) {
        isSuccess = ConfigManager::UpdataConfig<EventConfig>();
    } else if (file == CONFIG_CACHE_FILES[MODEL_CFG_INDEX]) {
        isSuccess = ConfigManager::UpdataConfig<ModelConfig>();
    }
    event.path = file;
    event.time = SecurityGuardUtils::GetDate();
    event.ret = isSuccess ? SUCCESS : FAILED;
    SGLOGD("file path=%{public}s, TIME=%{public}s, ret=%{public}d", event.path.c_str(), event.time.c_str(),
        event.ret);
    BigData::ReportConfigUpdateEvent(event);
   
    if (file != CONFIG_CACHE_FILES[EVENT_CFG_INDEX] && file != CONFIG_CACHE_FILES[MODEL_CFG_INDEX]) {
        return true;
    }
    if (!RemoveFile(file)) {
        SGLOGE("remove file error, %{public}s", strerror(errno));
    }
    return isSuccess;
}
} // OHOS::Security::SecurityGuard
