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

#ifndef SECURITY_GUARD_BIGDATA_H
#define SECURITY_GUARD_BIGDATA_H

#include "security_guard_define.h"

namespace OHOS::Security::SecurityGuard {
class BigData {
public:
    BigData() = delete;
    static void ReportObtainDataEvent(const ObtainDataEvent &event);
    static void ReportClassifyEvent(const ClassifyEvent &event);
    static void ReportSgSubscribeEvent(const SgSubscribeEvent &event);
    static void ReportSgUnsubscribeEvent(const SgUnsubscribeEvent &event);
    static void ReportConfigUpdateEvent(const ConfigUpdateEvent &event);
    static void ReportSetMuteEvent(const SgSubscribeEvent &event);
    static void ReportSetUnMuteEvent(const SgSubscribeEvent &event);
    static void ReportFileSystemStoreEvent(const FileSystemStoreErrMesg &mesg);
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_BIGDATA_H
