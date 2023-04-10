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

#include "directory_ex.h"
#include "string_ex.h"

#include "event_config.h"
#include "config_define.h"
#include "config_manager.h"
#include "model_config.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
std::shared_ptr<ConfigSubscriber> subscriber_ = nullptr;

namespace {
    const std::string HSDR_EVENT = "usual.event.HSDR_EVENT";
    const std::string CONFIG_ROOT_PATH = "/data/app/el1/100/base/com.ohos.security.hsdr/cache/";
    const std::string PATH_SEP = "/";
    const std::string PARAM_SEP = "|";
    const std::string NAME_SEP = ".";
    constexpr size_t NAME_COUNT = 2;
}

bool ConfigSubscriber::Subscribe(void)
{
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
    if (subscriber_ == nullptr) {
        return true;
    }
    return EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber_);
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
        for (const std::string &file : files) {
            SGLOGD("file path=%{public}s", file.c_str());
            if (file == CONFIG_CACHE_FILES[EVENT_CFG_INDEX]) {
                (void)ConfigManager::UpdataConfig<EventConfig>();
            } else if (file == CONFIG_CACHE_FILES[MODEL_CFG_INDEX]) {
                (void)ConfigManager::UpdataConfig<ModelConfig>();
            }
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
