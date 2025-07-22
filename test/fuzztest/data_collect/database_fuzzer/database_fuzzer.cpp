/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "database_fuzzer.h"

#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "securec.h"
#include <string_ex.h>

#define private public
#define protected public
#include "event_define.h"
#include "acquire_data_subscribe_manager.h"
#include "acquire_data_callback_proxy.h"
#include "data_collect_manager_callback_proxy.h"
#include "data_collect_manager_service.h"
#include "data_collect_manager_idl_stub.h"
#include "security_event_query_callback_proxy.h"
#include "database_helper.h"
#include "database_manager.h"
#include "database.h"
#include "risk_event_rdb_helper.h"
#include "store_define.h"
#undef private
#undef prtected

using namespace OHOS::Security::SecurityGuard;
namespace {
    constexpr int MAX_STRING_SIZE = 1024;
}
namespace OHOS {
class MockRemoteObject final : public IRemoteObject {
public:
    MockRemoteObject() : IRemoteObject(u"")
    {
    }
    int32_t GetObjectRefCount() { return 0; };
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) { return 0; };
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; };
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; };
    int Dump(int fd, const std::vector<std::u16string> &args) { return 0; };
};

bool DatabaseFuzzTest(const uint8_t* data, size_t size)
{
    Database database{};
    FuzzedDataProvider fdp(data, size);
    int32_t int32 = fdp.ConsumeIntegral<int32_t>();
    int64_t int64 = fdp.ConsumeIntegral<int64_t>();
    std::string string = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    GenericValues value{};
    std::vector<std::string> strings;
    std::vector<GenericValues> values{value};
    std::vector<std::string> columns{string};
    database.Insert(int64, string, value);
    database.BatchInsert(int64, string, values);
    database.Update(int32, string, value);
    database.Delete(int32, string, value);
    database.Query(string, value, values);
    database.ExecuteSql(string);
    database.ExecuteAndGetLong(int64, string, strings);
    database.Count(int64, string);
    database.BeginTransaction();
    database.RollBack();
    database.Commit();
    return true;
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::DatabaseFuzzTest(data, size);
    return 0;
}