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

#include "app_risk_detection_model.h"

#include <sstream>
#include <fstream>
#include <random>
#include <vector>
#include <unordered_set>
#include <memory>
#include <tuple>
#include <list>

#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "hilog/log.h"
#include "interfaces/hap_verify.h"

using OHOS::HiviewDFX::HiLog;
namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, 0xD002F10, "SG_APP_RISK_DETECTION" };
    constexpr int32_t FAILED = -1;
    constexpr int32_t SUCCESS = 0;

    constexpr const char *RISK_RESULT_STR[] = {"unknown", "risk", "safe"};
    constexpr uint32_t UNKNOWN_RESULT = 0;
    constexpr uint32_t SAFE_RESULT = 1;
    constexpr uint32_t RISK_REAULT = 2;
    constexpr uint32_t CHECK_SIGNATURE = 1;

    constexpr int64_t APP_SCAN_RESULT_ID = 1011016001;
    constexpr uint32_t CFG_FILE_MAX_SIZE = 1 * 1024 * 1024; // byte
}

struct DetectionCfg {
    std::string version;
    std::unordered_set<std::string> rules;
};

struct DetectionResult {
    std::string ToString() const
    {
        return RISK_RESULT_STR[result];
    }
    std::string packageName{}; // 应用包名
    std::string hash{};        // 应用hash
    uint64_t size{0};          // 文件大小
    uint32_t type{0};          // 威胁类型 signature 1 , url 2
    uint32_t result{0};        // 检测结果 unknown 0, risk  1 , safe 2
    std::string sample{};      // hex编码的采样包体
    uint64_t offset{0};        // 采样位置
};

struct CheckerArgs {
    const uint32_t modelId;
    const std::string &param;
    const std::shared_ptr<IConfigOperate> &cfgOpt;
    const std::shared_ptr<IDbOperate> &dbOpt;
};

#define IS_VALID_JSON(json, key, type) \
    (((json).find((key)) != (json).end() && (json).at((key)).is_##type())? true: false)

class Checker {
public:
    explicit Checker(const CheckerArgs &args)
        : modelId_(args.modelId),
          param_(args.param),
          cfgOpt_(args.cfgOpt),
          dbOpt_(args.dbOpt)
    {
    }
    virtual ~Checker() = default;
    virtual std::string Run() = 0;
protected:
    DetectionCfg UnmarshalCfg(const nlohmann::json &jsonObj, const std::string &rulesName) const
    {
        DetectionCfg config{};
        if (IS_VALID_JSON(jsonObj, "version", string)) {
            config.version = jsonObj.at("version").get<std::string>();
        }
        if (IS_VALID_JSON(jsonObj, rulesName.c_str(), array)) {
            config.rules = jsonObj.at(rulesName.c_str()).get<std::unordered_set<std::string>>();
        }
        return config;
    }

    std::optional<DetectionCfg> LoadCfg(const std::string &filePath, const std::string &rulesName) const
    {
        std::ifstream file = std::ifstream(filePath, std::ios::in);
        if (!file.is_open() || !file) {
            HiLog::Error(LABEL, "stream error, %{public}s", strerror(errno));
            return {};
        }
        if (file.seekg(0, std::ios_base::end).tellg() > CFG_FILE_MAX_SIZE) {
            HiLog::Error(LABEL, "cfg file is too large");
            file.close();
            return {};
        }
        file.seekg(0, std::ios_base::beg);
        nlohmann::json jsonObj = nlohmann::json::parse(file, nullptr, false);
        file.close();
        if (jsonObj.is_discarded()) {
            HiLog::Error(LABEL, "json is discarded");
            return {};
        }
        DetectionCfg config = UnmarshalCfg(jsonObj, rulesName);
        if (config.version.empty() || config.rules.empty()) {
            HiLog::Error(LABEL, "config is empty");
            return {};
        }

        HiLog::Info(LABEL, "config load completed, version=%{public}s, size=%{public}zu",
            config.version.c_str(), config.rules.size());
        return config;
    }

    std::string GetDate()
    {
        time_t timestamp = time(nullptr);
        struct tm timeInfo{};
        localtime_r(&timestamp, &timeInfo);
        char buf[32] = {};
        if (strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", &timeInfo) == 0) {
            return std::string{};
        }
        return std::string{buf};
    }

    void ReportResultEvent(const DetectionResult &result)
    {
        nlohmann::json jsonObj {
            { "package", result.packageName },
            { "hash", result.hash },
            { "size", result.size },
            { "type", result.type },
            { "result", result.result },
            { "sample", result.sample },
            { "offset", result.offset }
        };
        SecEvent event {
            .eventId = APP_SCAN_RESULT_ID,
            .version = "1.0",
            .date = GetDate(),
            .content = jsonObj.dump()
        };
        int32_t ret = dbOpt_->InsertEvent(event);
        HiLog::Info(LABEL, "insert app scan result, ret=%{public}d", ret);
    }

    const uint32_t modelId_;
    const std::string param_;
    std::shared_ptr<IConfigOperate> cfgOpt_;
    std::shared_ptr<IDbOperate> dbOpt_;
};

class UrlChecker : public Checker {
public:
    explicit UrlChecker(const CheckerArgs &args) : Checker(args) {}
    ~UrlChecker() override = default;
    std::string Run() override
    {
        return DetectionResult{}.ToString();
    }
};

namespace {
    constexpr uint32_t READ_BUFFER_SIZE = 4096;
    constexpr uint32_t SAMPLE_SIZE = 128;
    constexpr char HEX_STR[] = "0123456789abcdef";
}

class SignatureChecker : public Checker {
public:
    explicit SignatureChecker(const CheckerArgs &args) : Checker(args) {}
    ~SignatureChecker() override = default;
    std::string Run() override
    {
        auto config = LoadCfg("/data/service/el1/public/security_guard/signature_rule.cfg", "signatures");
        if (!config) {
            return DetectionResult{}.ToString();
        }

        auto parseResult = ParseHapFile();
        if (!parseResult) {
            return DetectionResult{}.ToString();
        }
        auto [signature, packageName] = *parseResult;
        HiLog::Info(LABEL, "VerifySignature:[%{public}s]", signature.c_str());

        DetectionResult result{};
        result.type = CHECK_SIGNATURE;
        result.packageName = packageName;
        result.result = ((config->rules.count(signature) != 0) ? SAFE_RESULT :  RISK_REAULT);
        FileSampling(result.hash, result.size, result.offset, result.sample);
        HiLog::Info(LABEL, "check signature finish, result = [%{public}s]", result.ToString().c_str());
        if (result.result != UNKNOWN_RESULT) {
            ReportResultEvent(result);
        }
        return result.ToString();
    }
private:
    std::string ConvertToHex(const std::vector<unsigned char> &buf)
    {
        std::string hexStr;
        for (auto c : buf) {
            hexStr.append({HEX_STR[(c >> 4) & 0xF], HEX_STR[c & 0xF]});
        }
        return hexStr;
    }

    std::string ConvertToHex(std::vector<char> buf)
    {
        return ConvertToHex(std::vector<unsigned char>{buf.begin(), buf.end()});
    }

    std::string FileSha256()
    {
        std::ifstream file(param_, std::ios::binary);
        if (!file) {
            HiLog::Error(LABEL, "open hap file failed");
            return std::string{};
        }
        std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX *)>evpCtx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        EVP_DigestInit_ex(evpCtx.get(), EVP_sha256(), nullptr);
        std::vector<char> buffer(READ_BUFFER_SIZE, 0);
        while (file.good()) {
            file.read(buffer.data(), buffer.size());
            EVP_DigestUpdate(evpCtx.get(), buffer.data(), file.gcount());
        }
        file.close();
        std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH, 0);
        unsigned int len;
        EVP_DigestFinal_ex(evpCtx.get(), hash.data(), &len);
        hash.resize(len);
        return  ConvertToHex(hash);
    }

    uint64_t RandomSampleOffset(uint64_t fileSize)
    {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib(0, fileSize);
        return (distrib(gen) / SAMPLE_SIZE) * SAMPLE_SIZE; // 取采样大小整数倍位置
    }

    std::string ReadSample(std::ifstream &file, uint64_t offset)
    {
        file.seekg(offset, std::ios_base::beg);
        std::vector<char> buffer(SAMPLE_SIZE, 0);
        file.read(buffer.data(), buffer.size());
        uint64_t readLen = file.gcount();
        buffer.resize(readLen);
        return ConvertToHex(buffer);
    }

    void FileSampling(std::string &hash, uint64_t &fileSize, uint64_t &offset, std::string &sample)
    {
        hash = FileSha256();
        std::ifstream file(param_, std::ios::binary);
        if (!file) {
            HiLog::Error(LABEL, "open hap file failed");
            return;
        }
        fileSize = file.seekg(0, std::ios_base::end).tellg();
        offset = RandomSampleOffset(fileSize);
        sample = ReadSample(file, offset);
        file.close();
    }

    std::optional<std::string> GetCertSignature(const std::string &certBase64)
    {
        auto bio = std::unique_ptr<BIO, decltype(&BIO_free)>{BIO_new(BIO_s_mem()), BIO_free};
        if (!bio) {
            HiLog::Error(LABEL, "Alloc BIO memory error");
            return {};
        }
        BIO_write(bio.get(), certBase64.c_str(), certBase64.length());
        auto x509 = std::unique_ptr<X509, decltype(&X509_free)>{
            PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free};
        if (!x509) {
            HiLog::Error(LABEL, "X509 read cert error\n");
            return {};
        }
        std::vector<unsigned char> md(EVP_MAX_MD_SIZE);
        unsigned int mdLen = 0;
        if (!X509_digest(x509.get(), EVP_sha256(), md.data(), &mdLen)) {
            HiLog::Error(LABEL, "X509 digest error\n");
            return {};
        }
        md.resize(mdLen);
        return ConvertToHex(md);
    }
    
    std::optional<std::tuple<std::string, std::string>> ParseHapFile()
    {
        Verify::HapVerifyResult hapVerifyV1Result;
        int ret = ParseHapProfile(param_, hapVerifyV1Result);
        if (ret != 0) {
            HiLog::Error(LABEL, "ParseHapProfile error, ret %{public}d", ret);
            return {};
        }
        Verify::ProvisionInfo info = hapVerifyV1Result.GetProvisionInfo();
        auto signature = GetCertSignature(info.bundleInfo.distributionCertificate);
        if (!signature) {
            return {};
        }
        HiLog::Info(LABEL, "ParseHapProfile completed");
        return std::make_tuple(*signature, info.bundleInfo.bundleName);
    }
};

std::tuple<std::unique_ptr<Checker>, std::string> CreateChecker(const CheckerArgs &args)
{
        ModelCfg cfg{};
        bool success = args.cfgOpt->GetModelConfig(args.modelId, cfg);
        if (success && cfg.type == "app") {
            if (cfg.appDetectionConfig.detectionCategory == "signature") {
                return std::make_tuple(std::make_unique<SignatureChecker>(args), std::string{});
            } else if (cfg.appDetectionConfig.detectionCategory == "url") {
                return std::make_tuple(std::make_unique<UrlChecker>(args), std::string{});
            }
        }

        HiLog::Error(LABEL, "app risk detection model not support, modelId=%{public}u, category=%{public}s",
            args.modelId, cfg.appDetectionConfig.detectionCategory.c_str());
        return std::make_tuple(nullptr, DetectionResult{}.ToString());
}

AppRiskDetectionModel::~AppRiskDetectionModel()
{
    HiLog::Info(LABEL, "func=%{public}s", __func__);
}

int32_t AppRiskDetectionModel::Init(std::shared_ptr<IModelManager> api)
{
    HiLog::Info(LABEL, "func=%{public}s", __func__);
    if (api == nullptr) {
        HiLog::Error(LABEL, "api is null");
        return FAILED;
    }
    dbOpt_ = api->GetDbOperate("risk_event");
    if (dbOpt_ == nullptr) {
        HiLog::Error(LABEL, "get db operate error");
        return FAILED;
    }
    cfgOpt_ = api->GetConfigOperate();
    if (cfgOpt_ == nullptr) {
        HiLog::Error(LABEL, "get config operate error");
        return FAILED;
    }
    return SUCCESS;
}

std::string AppRiskDetectionModel::GetResult(uint32_t modelId, const std::string &param)
{
    HiLog::Info(LABEL, "func=%{public}s", __func__);
    auto [checker, result] = CreateChecker(CheckerArgs{modelId, param, cfgOpt_, dbOpt_});
    if (!checker) {
        return result;
    }
    return checker->Run();
}

int32_t AppRiskDetectionModel::SubscribeResult(std::shared_ptr<IModelResultListener> listener)
{
    HiLog::Info(LABEL, "func=%{public}s", __func__);
    return SUCCESS;
}

void AppRiskDetectionModel::Release()
{
    HiLog::Info(LABEL, "func=%{public}s", __func__);
}

} // OHOS::Security::SecurityGuard

extern "C" OHOS::Security::SecurityGuard::IModel *GetModelApi()
{
    OHOS::Security::SecurityGuard::IModel *api =
        new (std::nothrow) OHOS::Security::SecurityGuard::AppRiskDetectionModel();
    return api;
}
