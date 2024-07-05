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
#include "local_app_config.h"
#include "global_app_config.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"

namespace OHOS::Security::SecurityGuard {
TimeEventRelatedCallBack ConfigSubscriber::timeEventCallBack_ {nullptr};
std::mutex ConfigSubscriber::callBackMutex_ {};

bool ConfigSubscriber::RegisterTimeEventRelatedCallBack(const TimeEventRelatedCallBack &callBack)
{
    std::lock_guard<std::mutex> lock(callBackMutex_);
    if (callBack == nullptr) {
        SGLOGE("callBack is null");
        return false;
    }
    SGLOGI("RegisterTimeEventRelatedCallBack...");
    timeEventCallBack_ = callBack;
    return true;
}

bool ConfigSubscriber::UpdateRelatedEventAnalysisCfg(const std::string &file)
{
    bool isSuccess = false;
    {
        std::lock_guard<std::mutex> lock(callBackMutex_);
        if (timeEventCallBack_ != nullptr) {
            isSuccess = timeEventCallBack_();
        }
    }
    if (isSuccess) {
        return SecurityGuardUtils::CopyFile(file, CONFIG_UPTATE_FILES[RELATED_EVENT_ANALYSIS_CFG_INDEX]);
    }
    return isSuccess;
}

bool ConfigSubscriber::UpdateConfig(const std::string &file)
{
    ConfigUpdateEvent event{};
    bool isSuccess = false;
    if (file == CONFIG_CACHE_FILES[EVENT_CFG_INDEX]) {
        isSuccess = ConfigManager::UpdataConfig<EventConfig>();
    } else if (file == CONFIG_CACHE_FILES[MODEL_CFG_INDEX]) {
        isSuccess = ConfigManager::UpdataConfig<ModelConfig>();
    } else if (file == CONFIG_CACHE_FILES[SIG_RULE_CFG_INDEX]) {
        isSuccess = SecurityGuardUtils::CopyFile(file, CONFIG_UPTATE_FILES[SIG_RULE_CFG_INDEX]);
    } else if (file == CONFIG_CACHE_FILES[URL_RULE_CFG_INDEX]) {
        isSuccess = SecurityGuardUtils::CopyFile(file, CONFIG_UPTATE_FILES[URL_RULE_CFG_INDEX]);
    } else if (file == CONFIG_CACHE_FILES[RELATED_EVENT_ANALYSIS_CFG_INDEX]) {
        isSuccess = UpdateRelatedEventAnalysisCfg(file);
    } else if (file == CONFIG_CACHE_FILES[LOCAL_APP_CFG_INDEX]) {
        isSuccess = ConfigManager::UpdataConfig<LocalAppConfig>();
    } else if (file == CONFIG_CACHE_FILES[GLOBAL_APP_CFG_INDEX]) {
        isSuccess = ConfigManager::UpdataConfig<GlobalAppConfig>();
    }
    event.path = file;
    event.time = SecurityGuardUtils::GetDate();
    event.ret = isSuccess ? SUCCESS : FAILED;
    SGLOGD("file path=%{public}s, TIME=%{public}s, ret=%{public}d", event.path.c_str(), event.time.c_str(),
        event.ret);
    BigData::ReportConfigUpdateEvent(event);
    bool success = RemoveFile(file);
    if (!success) {
        SGLOGW("remove file error, %{public}s", strerror(errno));
    }
    return isSuccess;
}
} // OHOS::Security::SecurityGuard
