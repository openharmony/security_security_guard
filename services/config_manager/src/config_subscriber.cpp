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

namespace OHOS::Security::SecurityGuard {
std::shared_ptr<ConfigSubscriber> ConfigSubscriber::subscriber_{nullptr};
std::mutex ConfigSubscriber::mutex_{};

namespace {
    const std::string HSDR_EVENT = "usual.event.HSDR_EVENT";
    const std::string PATH_SEP = "/";
    const std::string PARAM_SEP = "|";
    const std::string NAME_SEP = ".";
    constexpr size_t NAME_COUNT = 2;
}

bool ConfigSubscriber::Subscribe(void)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (subscriber_ == nullptr) {
        EventFwk::MatchingSkills matchingSkills;
        matchingSkills.AddEvent(HSDR_EVENT);
        EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
        subscriber_ = std::make_shared<ConfigSubscriber>(subscriberInfo);
        SGLOGI("begin Subscribe");
        return EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
    }
    return true;
};

bool ConfigSubscriber::UnSubscribe(void)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (subscriber_ == nullptr) {
        return true;
    }
    bool success = EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber_);
    if (success) {
        subscriber_ = nullptr;
    }
    return success;
};

void ConfigSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &eventData)
{
    // ex: "bundleName.moduleName | bundleName.moduleName"
    const std::string data = eventData.GetData();
    SGLOGI("OnReceiveEvent, data=%{public}s", data.c_str());
    std::vector<std::string> params;
    SplitStr(data, PARAM_SEP, params);
    for (const std::string &param : params) {
        std::vector<std::string> names;
        SplitStr(param, NAME_SEP, names);
        if (names.size() != NAME_COUNT) {
            continue;
        }

        const std::string configPath = CONFIG_ROOT_PATH + names[0] + PATH_SEP + names[1];
        std::vector<std::string> files;
        GetDirFiles(configPath, files);
        ConfigUpdateEvent event{};
        for (const std::string &file : files) {
            bool isSuccess = false;
            SGLOGD("file path=%{public}s", file.c_str());
            if (file == CONFIG_CACHE_FILES[EVENT_CFG_INDEX]) {
                isSuccess = ConfigManager::UpdataConfig<EventConfig>();
            } else if (file == CONFIG_CACHE_FILES[MODEL_CFG_INDEX]) {
                isSuccess = ConfigManager::UpdataConfig<ModelConfig>();
            } else if (file == CONFIG_CACHE_FILES[SIG_RULE_CFG_INDEX]) {
                isSuccess = SecurityGuardUtils::CopyFile(file, CONFIG_UPTATE_FILES[SIG_RULE_CFG_INDEX]);
            } else if (file == CONFIG_CACHE_FILES[URL_RULE_CFG_INDEX]) {
                isSuccess = SecurityGuardUtils::CopyFile(file, CONFIG_UPTATE_FILES[URL_RULE_CFG_INDEX]);
            }
            event.path = file.substr(configPath.length() + 1);
            event.time = SecurityGuardUtils::GetDate();
            event.ret = isSuccess ? SUCCESS : FAILED;
            SGLOGD("file path=%{public}s, TIME=%{public}s, ret=%{public}d", event.path.c_str(), event.time.c_str(),
                event.ret);
            BigData::ReportConfigUpdateEvent(event);
            bool success = RemoveFile(file);
            if (!success) {
                SGLOGW("remove file error, %{public}s", strerror(errno));
            }
        }
    }
}

ConfigSubscriber::~ConfigSubscriber()
{
    UnSubscribe();
}
} // OHOS::Security::SecurityGuard
