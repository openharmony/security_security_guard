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
#ifndef SECURITY_GUARD_LIB_LOADER_MOCK_H
#define SECURITY_GUARD_LIB_LOADER_MOCK_H

#include <string>
#include <dlfcn.h>
#include "gmock/gmock.h"
#include "security_collector_define.h"
#include "i_collector.h"

namespace OHOS::Security::SecurityCollector {
class BaseLibLoader {
public:
    BaseLibLoader() = default;
    virtual ~BaseLibLoader() = default;
    virtual ErrorCode LoadLib() = 0;
    virtual ICollector* CallGetCollector() = 0;
};

class LibLoader : public BaseLibLoader {
public:
    static LibLoader &GetInstance()
    {
        static LibLoader instance("test");
        return instance;
    };
    explicit LibLoader(const std::string soPath) {};
    ~LibLoader() override = default;

    MOCK_METHOD0(LoadLib, ErrorCode());
    MOCK_METHOD0(CallGetCollector, ICollector*());
};
}
#endif // SECURITY_GUARD_LIB_LOADER_MOCK_H