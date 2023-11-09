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

#include "lib_loader.h"

#include <dlfcn.h>
#include <string>

#include "security_collector_log.h"

namespace OHOS::Security::SecurityCollector {
LibLoader::LibLoader(const std::string soPath)
    : m_libPath(soPath)
{
}
 
LibLoader::~LibLoader()
{
    UnLoadLib();
}
 
ErrorCode LibLoader::LoadLib()
{
    LOGI("LoadLib start");
    m_handle = dlopen(m_libPath.c_str(), RTLD_LAZY);
    if (m_handle == nullptr) {
        LOGE("LoadLib m_handle error");
        m_isLoaded = false;
        return RET_DLOPEN_LIB_FAIL;
    }
    LOGI("dlopen success");
    m_isLoaded = true;
    return SUCCESS;
}
 
void LibLoader::UnLoadLib()
{
    LOGI("UnLoadLib start");
    if (!m_isLoaded) {
        LOGI("lib not found");
        return;
    }
    // should call dlclose(m_handle)
    LOGI("dlclose end");
    m_handle = nullptr;
    m_isLoaded = false;
}

ICollector* LibLoader::CallGetCollector()
{
    LOGI("CallGetCollector start");
    if (!m_isLoaded) {
        LOGE("lib not found");
        return nullptr;
    }
    typedef ICollector* (*GetCollectorFunc)();
    GetCollectorFunc getCollector = reinterpret_cast<GetCollectorFunc>(dlsym(m_handle, "GetCollector"));
    if (!getCollector) {
        LOGE("Failed to get GetCollector function");
        return nullptr;
    }
    return getCollector();
}
}