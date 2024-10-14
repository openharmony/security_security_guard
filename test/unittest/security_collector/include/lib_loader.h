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

#ifndef LIB_LOADER_H
#define LIB_LOADER_H

#include <string>
#include <dlfcn.h>

#include "security_collector_define.h"
#include "i_collector.h"

namespace OHOS::Security::SecurityCollector {

class LibLoader {
public:
    explicit LibLoader(const std::string soPath);
    ~LibLoader();
    ErrorCode LoadLib();
    ICollector* CallGetCollector();
 
private:
    void UnLoadLib();
    void* m_handle{ nullptr };
    std::atomic<bool> m_isLoaded{ false };
    const std::string m_libPath;
};
}
#endif // LIB_LOADER_H