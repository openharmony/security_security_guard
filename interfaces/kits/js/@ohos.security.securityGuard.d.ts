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

import { AsyncCallback } from './@ohos.base';

/**
 * Provides security event management and security model management.
 * Based on event information, you will be able to analyze the running status of devices.
 *
 * @namespace securityGuard
 * @syscap SystemCapability.Security.SecurityGuard
 * @since 10
 */
declare namespace securityGuard {
  /**
   * Enum for event id type.
   *
   * @enum { number }
   * @syscap SystemCapability.Security.SecurityGuard
   * @since 10
   */
  enum EventIdType {
    /**
     * The value of printer event id.
     *
     * @syscap SystemCapability.Security.SecurityGuard
     * @since 10
     */
    PRINTER_EVENT_ID = 1011015004
  }

  /**
   * Enum for model id type.
   *
   * @enum { number }
   * @syscap SystemCapability.Security.SecurityGuard
   * @since 10
   */
  enum ModelIdType {
    /**
     * The value of root scan model id.
     *
     * @syscap SystemCapability.Security.SecurityGuard
     * @since 10
     */
    ROOT_SCAN_MODEL_ID = 3001000000,

    /**
     * The value of device completeness model id.
     *
     * @syscap SystemCapability.Security.SecurityGuard
     * @since 10
     */
    DEVICE_COMPLETENESS_MODEL_ID = 3001000001,

    /**
     * The value of physical machine detection model id.
     *
     * @syscap SystemCapability.Security.SecurityGuard
     * @since 10
     */
    PHYSICAL_MACHINE_DETECTION_MODEL_ID = 3001000002,

    /**
     * The value of security audit model id.
     *
     * @syscap SystemCapability.Security.SecurityGuard
     * @since 10
     */
    SECURITY_AUDIT_MODEL_ID = 3001000003
  }

  /**
   * Provides the EventInfo type, including the event id, version info, report content.
   *
   * @typedef EventInfo
   * @syscap SystemCapability.Security.SecurityGuard
   * @since 10
   */
  interface EventInfo {
    /**
     * The event id
     *
     * @type { EventIdType }
     * @syscap SystemCapability.Security.SecurityGuard
     * @since 10
     */
    eventId: EventIdType;

    /**
     * The version info
     *
     * @type { string }
     * @syscap SystemCapability.Security.SecurityGuard
     * @since 10
     */
    version: string;

    /**
     * The report content
     *
     * @type { string }
     * @syscap SystemCapability.Security.SecurityGuard
     * @since 10
     */
    content: string;
  }

  /**
   * Report security information to the security guard.
   *
   * @permission ohos.permission.securityguard.REPORT_SECURITY_INFO
   * @param { EventInfo } info - indicates the infomation to be reported.
   * @throws { BusinessError } 201 - check permission fail.
   * @throws { BusinessError } 401 - invalid parameters.
   * @returns { number } the reported result.
   * @syscap SystemCapability.Security.SecurityGuard
   * @since 10
   */
  function reportSecurityInfo(info: EventInfo): number;

  /**
   * Provides the conditions of requestSecurityEventInfo, including the event id, the begin time and the end time.
   *
   * @typedef Conditions
   * @syscap SystemCapability.Security.SecurityGuard
   * @since 10
   */
  interface Conditions {
    /**
     * The security event ids.
     *
     * @type { Array<number> }
     * @syscap SystemCapability.Security.SecurityGuard
     * @since 10
     */
    eventIds: Array<number>;

    /**
     * The begin time.
     *
     * @type { ?string }
     * @syscap SystemCapability.Security.SecurityGuard
     * @since 10
     */
    beginTime?: string;

    /**
     * The end time.
     *
     * @type { ?string }
     * @syscap SystemCapability.Security.SecurityGuard
     * @since 10
     */
    endTime?: string;
  }

  /**
   * Definition the request data response.
   *
   * @interface Response
   * @syscap SystemCapability.Security.SecurityGuard
   * @since 10
   */
  interface Response {
    /**
     * Triggered when data is transferred.
     *
     * @param { 'data' } type - indicates the type of subscribe event.
     * @param { function } callback - indicates the callback of the data transferred.
     * @syscap SystemCapability.Security.SecurityGuard
     * @since 10
     */
    on(type: 'data', callback: (chunk: string) => void): void;

    /**
     * Triggered when data transfer ends.
     *
     * @param { 'end' } type - indicates the type of subscribe event.
     * @param { function } callback - indicates the callback of the data transfer ends.
     * @syscap SystemCapability.Security.SecurityGuard
     * @since 10
     */
    on(type: 'end', callback: () => void): void;

    /**
     * Triggered when an error occurs in data transfer.
     *
     * @param { 'error' } type - indicates the type of subscribe event.
     * @param { function } callback - indicates the callback of the error occurs in data transfer.
     * @syscap SystemCapability.Security.SecurityGuard
     * @since 10
     */
    on(type: 'error', callback: (error: string) => void): void;
  }

  /**
   * Request security event infomation from security guard.
   *
   * @permission ohos.permission.securityguard.REQUEST_SECURITY_EVENT_INFO
   * @param { string } deviceId - deviceId indicates device id, local device is "".
   * @param { Conditions } conditions - conditions of request security event infomation.
   * @param { function } callback - callback of receiving the request data.
   * @throws { BusinessError } 201 - check permission fail.
   * @throws { BusinessError } 401 - invalid parameters.
   * @syscap SystemCapability.Security.SecurityGuard
   * @since 10
   */
  function requestSecurityEventInfo(deviceId: string, conditions: Conditions, callback: (res: Response) => void): void;

  /**
   * Provides the SecurityModelResult type, including the device id, security model id, result of security model.
   *
   * @typedef SecurityModelResult
   * @syscap SystemCapability.Security.SecurityGuard
   * @since 10
   */
  interface SecurityModelResult {
    /**
     * The device id
     *
     * @type { string }
     * @syscap SystemCapability.Security.SecurityGuard
     * @since 10
     */
    deviceId: string;

    /**
     * The security model id
     *
     * @type { ModelIdType }
     * @syscap SystemCapability.Security.SecurityGuard
     * @since 10
     */
    modelId: ModelIdType;

    /**
     * The result of security model
     *
     * @type { string }
     * @syscap SystemCapability.Security.SecurityGuard
     * @since 10
     */
    result: string;
  }

  /**
   * Request security model result from security guard.
   *
   * @permission ohos.permission.securityguard.REQUEST_SECURITY_MODEL_RESULT
   * @param { string } deviceId - deviceId indicates device id, local device is "".
   * @param { ModelIdType } modelId - modelId indicates the security model id.
   * @param { AsyncCallback<SecurityModelResult> } callback - the callback of requestSecurityModelResult.
   * @throws { BusinessError } 201 - check permission fail.
   * @throws { BusinessError } 401 - invalid parameters.
   * @syscap SystemCapability.Security.SecurityGuard
   * @since 10
   */
  function requestSecurityModelResult(
      deviceId: string,
      modelId: ModelIdType,
      callback: AsyncCallback<SecurityModelResult>
  ): void;
  /**
   * Request security model result from security guard.
   *
   * @permission ohos.permission.securityguard.REQUEST_SECURITY_MODEL_RESULT
   * @param { string } deviceId - deviceId indicates device id, local device is "".
   * @param { ModelIdType } modelId - modelId indicates the security model id.
   * @throws { BusinessError } 201 - check permission fail.
   * @throws { BusinessError } 401 - invalid parameters.
   * @returns { Promise<SecurityModelResult> } the promise returned by the function.
   * @syscap SystemCapability.Security.SecurityGuard
   * @since 10
   */
  function requestSecurityModelResult(deviceId: string, modelId: ModelIdType): Promise<SecurityModelResult>;

  /**
   * Set the state of the security model switch.
   *
   * @permission ohos.permission.securityguard.SET_MODEL_STATE
   * @param { ModelIdType } modelId - modelId indicates the security model id.
   * @param { boolean } enable - the state of the security model switch to be set.
   * @throws { BusinessError } 201 - check permission fail.
   * @throws { BusinessError } 401 - invalid parameters.
   * @returns { number } the function result.
   * @syscap SystemCapability.Security.SecurityGuard
   * @since 10
   */
  function setModelState(modelId: ModelIdType, enable: boolean): number;
}

export default securityGuard;
