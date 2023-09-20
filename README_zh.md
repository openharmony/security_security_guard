# 设备风险管理平台

- 简介
- 目录
- 说明

## 简介

设备风险管理平台（SecurityGuard，简称SG）向应用提供风险分析能力，包括root检测，设备完整性检测，物理真机检测等功能。

SG模块可以分为如下三大部分：

- SG 接口层：提供SG API供应用调用。

- SG 基础服务层：实现SG数据管理、模型管理、配置管理等功能。

- SG 安全模型：

  1）root检测模型：提供root检测能力

  2）设备完整性检测模型：提供设备完整性检测能力

  3）物理机检测模型：提供物理机检测能力


SG部件架构如下图所示：

![ohos_security_guard_architecture](figures/ohos_security_guard_architecture.png)

## 目录

```
├── build                              # 编译配置文件
├── frameworks                         # 框架代码, 作为基础功能目录, 被interfaces和services使用.
├── interfaces                         # 接口API代码
│   ├── inner_api                      # inner api接口
│   └── kits                           # 对外api接口
├── services                           # 服务框架代码
│   └── config_manager                 # SG 配置管理代码
│   ├── data_collect                   # SG 数据管理代码
│   └── risk_classify                  # SG 模型管理代码
└── test                               # 测试代码存放目录
```

## 说明

### 接口说明

[接口文档](https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis/js-apis-securityGuard.md)

## 相关仓

**安全子系统**

[security\_security\_guard](https://gitee.com/openharmony/security_security_guard)