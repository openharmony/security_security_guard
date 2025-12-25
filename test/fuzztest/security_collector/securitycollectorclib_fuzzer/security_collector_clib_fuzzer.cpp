/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "securec.h"
#include "collector_cfg_marshalling.h"
#include "data_collection.h"
#include "lib_loader.h"
#include "security_collector_manager_callback_proxy.h"
#include "security_collector_manager_service.h"
#include "security_collector_manager_stub.h"
#include "security_collector_run_manager.h"
#include "security_collector_subscriber_manager.h"
#include "security_collector_subscriber.h"
#include "event_define.h"

using namespace OHOS::Security::SecurityCollector;
using namespace OHOS;

constexpr int FUZZ_COLLECTOR_SUBCRIBE = 0;
constexpr int FUZZ_COLLECTOR_UNSUBCRIBE = 1;
constexpr int FUZZ_COLLECTOR_START = 2;
constexpr int FUZZ_COLLECTOR_STOP = 3;
constexpr int FUZZ_SECURITY_EVENT_QUERY = 4;
constexpr int FUZZ_SECURITY_EVENT_MUTE = 5;
constexpr int FUZZ_SECURITY_EVENT_UNMUTE = 6;
constexpr int MAX_STRING_SIZE = 1024;
constexpr int32_t TEST_SA_ID = 3525;
SecurityCollectorManagerService g_service(TEST_SA_ID, true);

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

void SetPermission()
{
    static const char *permission[] = {
        "ohos.permission.COLLECT_SECURITY_EVENT",
        "ohos.permission.QUERY_SECURITY_EVENT"
    };
    uint64_t tokenId;
    NativeTokenInfoParams infoParams = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = permission,
        .acls = nullptr,
        .processName = "SecurityCollectorClibFuzzTest",
        .aplStr = "system_basic",
    };
    tokenId = GetAccessTokenId(&infoParams);
    SetSelfTokenID(tokenId);
    Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

extern "C" int FuzzSecurityCollector(FuzzedDataProvider &fdp)
{
    int64_t eventId = fdp.ConsumeIntegral<int64_t>();
    std::string str = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    SecurityCollectorEventMuteFilter fil{};
    Security::SecurityCollector::Event event{eventId, str, str, str};
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    SecurityEventRuler ruler(eventId);
    std::vector<SecurityEventRuler> rulers;
    rulers.emplace_back(ruler);
    SecurityCollectorSubscribeInfo subscribeInfo{event};
    std::vector<SecurityEvent> events{};

    static const int ipccodes[] = {0, 1, 2, 3, 4, 5, 6};
    int code = fdp.PickValueInArray(ipccodes);
    switch (code) {
        case FUZZ_COLLECTOR_SUBCRIBE: {
            g_service.Subscribe(subscribeInfo, obj);
            break;
        }
        case FUZZ_COLLECTOR_UNSUBCRIBE: {
            g_service.Unsubscribe(obj);
            break;
        }
        case FUZZ_COLLECTOR_START: {
            g_service.CollectorStart(subscribeInfo, obj);
            break;
        }
        case FUZZ_COLLECTOR_STOP: {
            g_service.CollectorStop(subscribeInfo, obj);
            break;
        }
        case FUZZ_SECURITY_EVENT_QUERY: {
            g_service.QuerySecurityEvent(rulers, events);
            break;
        }
        case FUZZ_SECURITY_EVENT_MUTE: {
            g_service.AddFilter(fil);
            break;
        }
        case FUZZ_SECURITY_EVENT_UNMUTE: {
            g_service.RemoveFilter(fil);
            break;
        }
        default:
            break;
    }
    return 0;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    SetPermission();
    g_service.OnStart();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    FuzzedDataProvider fdp(data, size);
    FuzzSecurityCollector(fdp);
    return 0;
}
