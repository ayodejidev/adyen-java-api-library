/*
 * Management API
 *
 * The version of the OpenAPI document: 3
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.management;

import java.util.Objects;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import com.adyen.model.management.AdditionalSettings;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.annotation.JsonValue;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;


/**
 * CreateMerchantWebhookRequest
 */
@JsonPropertyOrder({
  CreateMerchantWebhookRequest.JSON_PROPERTY_ACCEPTS_EXPIRED_CERTIFICATE,
  CreateMerchantWebhookRequest.JSON_PROPERTY_ACCEPTS_SELF_SIGNED_CERTIFICATE,
  CreateMerchantWebhookRequest.JSON_PROPERTY_ACCEPTS_UNTRUSTED_ROOT_CERTIFICATE,
  CreateMerchantWebhookRequest.JSON_PROPERTY_ACTIVE,
  CreateMerchantWebhookRequest.JSON_PROPERTY_ADDITIONAL_SETTINGS,
  CreateMerchantWebhookRequest.JSON_PROPERTY_COMMUNICATION_FORMAT,
  CreateMerchantWebhookRequest.JSON_PROPERTY_DESCRIPTION,
  CreateMerchantWebhookRequest.JSON_PROPERTY_ENCRYPTION_PROTOCOL,
  CreateMerchantWebhookRequest.JSON_PROPERTY_NETWORK_TYPE,
  CreateMerchantWebhookRequest.JSON_PROPERTY_PASSWORD,
  CreateMerchantWebhookRequest.JSON_PROPERTY_POPULATE_SOAP_ACTION_HEADER,
  CreateMerchantWebhookRequest.JSON_PROPERTY_TYPE,
  CreateMerchantWebhookRequest.JSON_PROPERTY_URL,
  CreateMerchantWebhookRequest.JSON_PROPERTY_USERNAME
})

public class CreateMerchantWebhookRequest {
  public static final String JSON_PROPERTY_ACCEPTS_EXPIRED_CERTIFICATE = "acceptsExpiredCertificate";
  private Boolean acceptsExpiredCertificate;

  public static final String JSON_PROPERTY_ACCEPTS_SELF_SIGNED_CERTIFICATE = "acceptsSelfSignedCertificate";
  private Boolean acceptsSelfSignedCertificate;

  public static final String JSON_PROPERTY_ACCEPTS_UNTRUSTED_ROOT_CERTIFICATE = "acceptsUntrustedRootCertificate";
  private Boolean acceptsUntrustedRootCertificate;

  public static final String JSON_PROPERTY_ACTIVE = "active";
  private Boolean active;

  public static final String JSON_PROPERTY_ADDITIONAL_SETTINGS = "additionalSettings";
  private AdditionalSettings additionalSettings;

  /**
   * Format or protocol for receiving webhooks. Possible values: * **soap** * **http** * **json** 
   */
  public enum CommunicationFormatEnum {
    HTTP("http"),
    
    JSON("json"),
    
    SOAP("soap");

    private String value;

    CommunicationFormatEnum(String value) {
      this.value = value;
    }

    @JsonValue
    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    @JsonCreator
    public static CommunicationFormatEnum fromValue(String value) {
      for (CommunicationFormatEnum b : CommunicationFormatEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_COMMUNICATION_FORMAT = "communicationFormat";
  private CommunicationFormatEnum communicationFormat;

  public static final String JSON_PROPERTY_DESCRIPTION = "description";
  private String description;

  /**
   * SSL version to access the public webhook URL specified in the &#x60;url&#x60; field. Possible values: * **TLSv1.3** * **TLSv1.2** * **HTTP** - Only allowed on Test environment.  If not specified, the webhook will use &#x60;sslVersion&#x60;: **TLSv1.2**.
   */
  public enum EncryptionProtocolEnum {
    HTTP("HTTP"),
    
    TLSV1_2("TLSv1.2"),
    
    TLSV1_3("TLSv1.3");

    private String value;

    EncryptionProtocolEnum(String value) {
      this.value = value;
    }

    @JsonValue
    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    @JsonCreator
    public static EncryptionProtocolEnum fromValue(String value) {
      for (EncryptionProtocolEnum b : EncryptionProtocolEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_ENCRYPTION_PROTOCOL = "encryptionProtocol";
  private EncryptionProtocolEnum encryptionProtocol;

  /**
   * Network type for Terminal API notification webhooks. Possible values: * **public** * **local**  Default Value: **public**.
   */
  public enum NetworkTypeEnum {
    LOCAL("local"),
    
    PUBLIC("public");

    private String value;

    NetworkTypeEnum(String value) {
      this.value = value;
    }

    @JsonValue
    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    @JsonCreator
    public static NetworkTypeEnum fromValue(String value) {
      for (NetworkTypeEnum b : NetworkTypeEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_NETWORK_TYPE = "networkType";
  private NetworkTypeEnum networkType;

  public static final String JSON_PROPERTY_PASSWORD = "password";
  private String password;

  public static final String JSON_PROPERTY_POPULATE_SOAP_ACTION_HEADER = "populateSoapActionHeader";
  private Boolean populateSoapActionHeader;

  public static final String JSON_PROPERTY_TYPE = "type";
  private String type;

  public static final String JSON_PROPERTY_URL = "url";
  private String url;

  public static final String JSON_PROPERTY_USERNAME = "username";
  private String username;

  public CreateMerchantWebhookRequest() { 
  }

  /**
   * Indicates if expired SSL certificates are accepted. Default value: **false**.
   *
   * @param acceptsExpiredCertificate
   * @return the current {@code CreateMerchantWebhookRequest} instance, allowing for method chaining
   */
  public CreateMerchantWebhookRequest acceptsExpiredCertificate(Boolean acceptsExpiredCertificate) {
    this.acceptsExpiredCertificate = acceptsExpiredCertificate;
    return this;
  }

  /**
   * Indicates if expired SSL certificates are accepted. Default value: **false**.
   * @return acceptsExpiredCertificate
   */
  @ApiModelProperty(value = "Indicates if expired SSL certificates are accepted. Default value: **false**.")
  @JsonProperty(JSON_PROPERTY_ACCEPTS_EXPIRED_CERTIFICATE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Boolean getAcceptsExpiredCertificate() {
    return acceptsExpiredCertificate;
  }

  /**
   * Indicates if expired SSL certificates are accepted. Default value: **false**.
   *
   * @param acceptsExpiredCertificate
   */ 
  @JsonProperty(JSON_PROPERTY_ACCEPTS_EXPIRED_CERTIFICATE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAcceptsExpiredCertificate(Boolean acceptsExpiredCertificate) {
    this.acceptsExpiredCertificate = acceptsExpiredCertificate;
  }

  /**
   * Indicates if self-signed SSL certificates are accepted. Default value: **false**.
   *
   * @param acceptsSelfSignedCertificate
   * @return the current {@code CreateMerchantWebhookRequest} instance, allowing for method chaining
   */
  public CreateMerchantWebhookRequest acceptsSelfSignedCertificate(Boolean acceptsSelfSignedCertificate) {
    this.acceptsSelfSignedCertificate = acceptsSelfSignedCertificate;
    return this;
  }

  /**
   * Indicates if self-signed SSL certificates are accepted. Default value: **false**.
   * @return acceptsSelfSignedCertificate
   */
  @ApiModelProperty(value = "Indicates if self-signed SSL certificates are accepted. Default value: **false**.")
  @JsonProperty(JSON_PROPERTY_ACCEPTS_SELF_SIGNED_CERTIFICATE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Boolean getAcceptsSelfSignedCertificate() {
    return acceptsSelfSignedCertificate;
  }

  /**
   * Indicates if self-signed SSL certificates are accepted. Default value: **false**.
   *
   * @param acceptsSelfSignedCertificate
   */ 
  @JsonProperty(JSON_PROPERTY_ACCEPTS_SELF_SIGNED_CERTIFICATE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAcceptsSelfSignedCertificate(Boolean acceptsSelfSignedCertificate) {
    this.acceptsSelfSignedCertificate = acceptsSelfSignedCertificate;
  }

  /**
   * Indicates if untrusted SSL certificates are accepted. Default value: **false**.
   *
   * @param acceptsUntrustedRootCertificate
   * @return the current {@code CreateMerchantWebhookRequest} instance, allowing for method chaining
   */
  public CreateMerchantWebhookRequest acceptsUntrustedRootCertificate(Boolean acceptsUntrustedRootCertificate) {
    this.acceptsUntrustedRootCertificate = acceptsUntrustedRootCertificate;
    return this;
  }

  /**
   * Indicates if untrusted SSL certificates are accepted. Default value: **false**.
   * @return acceptsUntrustedRootCertificate
   */
  @ApiModelProperty(value = "Indicates if untrusted SSL certificates are accepted. Default value: **false**.")
  @JsonProperty(JSON_PROPERTY_ACCEPTS_UNTRUSTED_ROOT_CERTIFICATE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Boolean getAcceptsUntrustedRootCertificate() {
    return acceptsUntrustedRootCertificate;
  }

  /**
   * Indicates if untrusted SSL certificates are accepted. Default value: **false**.
   *
   * @param acceptsUntrustedRootCertificate
   */ 
  @JsonProperty(JSON_PROPERTY_ACCEPTS_UNTRUSTED_ROOT_CERTIFICATE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAcceptsUntrustedRootCertificate(Boolean acceptsUntrustedRootCertificate) {
    this.acceptsUntrustedRootCertificate = acceptsUntrustedRootCertificate;
  }

  /**
   * Indicates if the webhook configuration is active. The field must be **true** for us to send webhooks about events related an account.
   *
   * @param active
   * @return the current {@code CreateMerchantWebhookRequest} instance, allowing for method chaining
   */
  public CreateMerchantWebhookRequest active(Boolean active) {
    this.active = active;
    return this;
  }

  /**
   * Indicates if the webhook configuration is active. The field must be **true** for us to send webhooks about events related an account.
   * @return active
   */
  @ApiModelProperty(required = true, value = "Indicates if the webhook configuration is active. The field must be **true** for us to send webhooks about events related an account.")
  @JsonProperty(JSON_PROPERTY_ACTIVE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Boolean getActive() {
    return active;
  }

  /**
   * Indicates if the webhook configuration is active. The field must be **true** for us to send webhooks about events related an account.
   *
   * @param active
   */ 
  @JsonProperty(JSON_PROPERTY_ACTIVE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setActive(Boolean active) {
    this.active = active;
  }

  /**
   * additionalSettings
   *
   * @param additionalSettings
   * @return the current {@code CreateMerchantWebhookRequest} instance, allowing for method chaining
   */
  public CreateMerchantWebhookRequest additionalSettings(AdditionalSettings additionalSettings) {
    this.additionalSettings = additionalSettings;
    return this;
  }

  /**
   * additionalSettings
   * @return additionalSettings
   */
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_ADDITIONAL_SETTINGS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public AdditionalSettings getAdditionalSettings() {
    return additionalSettings;
  }

  /**
   * additionalSettings
   *
   * @param additionalSettings
   */ 
  @JsonProperty(JSON_PROPERTY_ADDITIONAL_SETTINGS)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAdditionalSettings(AdditionalSettings additionalSettings) {
    this.additionalSettings = additionalSettings;
  }

  /**
   * Format or protocol for receiving webhooks. Possible values: * **soap** * **http** * **json** 
   *
   * @param communicationFormat
   * @return the current {@code CreateMerchantWebhookRequest} instance, allowing for method chaining
   */
  public CreateMerchantWebhookRequest communicationFormat(CommunicationFormatEnum communicationFormat) {
    this.communicationFormat = communicationFormat;
    return this;
  }

  /**
   * Format or protocol for receiving webhooks. Possible values: * **soap** * **http** * **json** 
   * @return communicationFormat
   */
  @ApiModelProperty(example = "soap", required = true, value = "Format or protocol for receiving webhooks. Possible values: * **soap** * **http** * **json** ")
  @JsonProperty(JSON_PROPERTY_COMMUNICATION_FORMAT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public CommunicationFormatEnum getCommunicationFormat() {
    return communicationFormat;
  }

  /**
   * Format or protocol for receiving webhooks. Possible values: * **soap** * **http** * **json** 
   *
   * @param communicationFormat
   */ 
  @JsonProperty(JSON_PROPERTY_COMMUNICATION_FORMAT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCommunicationFormat(CommunicationFormatEnum communicationFormat) {
    this.communicationFormat = communicationFormat;
  }

  /**
   * Your description for this webhook configuration.
   *
   * @param description
   * @return the current {@code CreateMerchantWebhookRequest} instance, allowing for method chaining
   */
  public CreateMerchantWebhookRequest description(String description) {
    this.description = description;
    return this;
  }

  /**
   * Your description for this webhook configuration.
   * @return description
   */
  @ApiModelProperty(value = "Your description for this webhook configuration.")
  @JsonProperty(JSON_PROPERTY_DESCRIPTION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getDescription() {
    return description;
  }

  /**
   * Your description for this webhook configuration.
   *
   * @param description
   */ 
  @JsonProperty(JSON_PROPERTY_DESCRIPTION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setDescription(String description) {
    this.description = description;
  }

  /**
   * SSL version to access the public webhook URL specified in the &#x60;url&#x60; field. Possible values: * **TLSv1.3** * **TLSv1.2** * **HTTP** - Only allowed on Test environment.  If not specified, the webhook will use &#x60;sslVersion&#x60;: **TLSv1.2**.
   *
   * @param encryptionProtocol
   * @return the current {@code CreateMerchantWebhookRequest} instance, allowing for method chaining
   */
  public CreateMerchantWebhookRequest encryptionProtocol(EncryptionProtocolEnum encryptionProtocol) {
    this.encryptionProtocol = encryptionProtocol;
    return this;
  }

  /**
   * SSL version to access the public webhook URL specified in the &#x60;url&#x60; field. Possible values: * **TLSv1.3** * **TLSv1.2** * **HTTP** - Only allowed on Test environment.  If not specified, the webhook will use &#x60;sslVersion&#x60;: **TLSv1.2**.
   * @return encryptionProtocol
   */
  @ApiModelProperty(example = "TLSv1.2", value = "SSL version to access the public webhook URL specified in the `url` field. Possible values: * **TLSv1.3** * **TLSv1.2** * **HTTP** - Only allowed on Test environment.  If not specified, the webhook will use `sslVersion`: **TLSv1.2**.")
  @JsonProperty(JSON_PROPERTY_ENCRYPTION_PROTOCOL)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public EncryptionProtocolEnum getEncryptionProtocol() {
    return encryptionProtocol;
  }

  /**
   * SSL version to access the public webhook URL specified in the &#x60;url&#x60; field. Possible values: * **TLSv1.3** * **TLSv1.2** * **HTTP** - Only allowed on Test environment.  If not specified, the webhook will use &#x60;sslVersion&#x60;: **TLSv1.2**.
   *
   * @param encryptionProtocol
   */ 
  @JsonProperty(JSON_PROPERTY_ENCRYPTION_PROTOCOL)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setEncryptionProtocol(EncryptionProtocolEnum encryptionProtocol) {
    this.encryptionProtocol = encryptionProtocol;
  }

  /**
   * Network type for Terminal API notification webhooks. Possible values: * **public** * **local**  Default Value: **public**.
   *
   * @param networkType
   * @return the current {@code CreateMerchantWebhookRequest} instance, allowing for method chaining
   */
  public CreateMerchantWebhookRequest networkType(NetworkTypeEnum networkType) {
    this.networkType = networkType;
    return this;
  }

  /**
   * Network type for Terminal API notification webhooks. Possible values: * **public** * **local**  Default Value: **public**.
   * @return networkType
   */
  @ApiModelProperty(value = "Network type for Terminal API notification webhooks. Possible values: * **public** * **local**  Default Value: **public**.")
  @JsonProperty(JSON_PROPERTY_NETWORK_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public NetworkTypeEnum getNetworkType() {
    return networkType;
  }

  /**
   * Network type for Terminal API notification webhooks. Possible values: * **public** * **local**  Default Value: **public**.
   *
   * @param networkType
   */ 
  @JsonProperty(JSON_PROPERTY_NETWORK_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setNetworkType(NetworkTypeEnum networkType) {
    this.networkType = networkType;
  }

  /**
   * Password to access the webhook URL.
   *
   * @param password
   * @return the current {@code CreateMerchantWebhookRequest} instance, allowing for method chaining
   */
  public CreateMerchantWebhookRequest password(String password) {
    this.password = password;
    return this;
  }

  /**
   * Password to access the webhook URL.
   * @return password
   */
  @ApiModelProperty(value = "Password to access the webhook URL.")
  @JsonProperty(JSON_PROPERTY_PASSWORD)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getPassword() {
    return password;
  }

  /**
   * Password to access the webhook URL.
   *
   * @param password
   */ 
  @JsonProperty(JSON_PROPERTY_PASSWORD)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPassword(String password) {
    this.password = password;
  }

  /**
   * Indicates if the SOAP action header needs to be populated. Default value: **false**.  Only applies if &#x60;communicationFormat&#x60;: **soap**.
   *
   * @param populateSoapActionHeader
   * @return the current {@code CreateMerchantWebhookRequest} instance, allowing for method chaining
   */
  public CreateMerchantWebhookRequest populateSoapActionHeader(Boolean populateSoapActionHeader) {
    this.populateSoapActionHeader = populateSoapActionHeader;
    return this;
  }

  /**
   * Indicates if the SOAP action header needs to be populated. Default value: **false**.  Only applies if &#x60;communicationFormat&#x60;: **soap**.
   * @return populateSoapActionHeader
   */
  @ApiModelProperty(value = "Indicates if the SOAP action header needs to be populated. Default value: **false**.  Only applies if `communicationFormat`: **soap**.")
  @JsonProperty(JSON_PROPERTY_POPULATE_SOAP_ACTION_HEADER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Boolean getPopulateSoapActionHeader() {
    return populateSoapActionHeader;
  }

  /**
   * Indicates if the SOAP action header needs to be populated. Default value: **false**.  Only applies if &#x60;communicationFormat&#x60;: **soap**.
   *
   * @param populateSoapActionHeader
   */ 
  @JsonProperty(JSON_PROPERTY_POPULATE_SOAP_ACTION_HEADER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPopulateSoapActionHeader(Boolean populateSoapActionHeader) {
    this.populateSoapActionHeader = populateSoapActionHeader;
  }

  /**
   * The type of webhook that is being created. Possible values are:  - **standard** - **account-settings-notification** - **banktransfer-notification** - **boletobancario-notification** - **directdebit-notification** - **ach-notification-of-change-notification** - **pending-notification** - **ideal-notification** - **ideal-pending-notification** - **report-notification** - **rreq-notification** - **terminal-settings** - **terminal-boarding**  Find out more about [standard notification webhooks](https://docs.adyen.com/development-resources/webhooks/understand-notifications#event-codes) and [other types of notifications](https://docs.adyen.com/development-resources/webhooks/understand-notifications#other-notifications).
   *
   * @param type
   * @return the current {@code CreateMerchantWebhookRequest} instance, allowing for method chaining
   */
  public CreateMerchantWebhookRequest type(String type) {
    this.type = type;
    return this;
  }

  /**
   * The type of webhook that is being created. Possible values are:  - **standard** - **account-settings-notification** - **banktransfer-notification** - **boletobancario-notification** - **directdebit-notification** - **ach-notification-of-change-notification** - **pending-notification** - **ideal-notification** - **ideal-pending-notification** - **report-notification** - **rreq-notification** - **terminal-settings** - **terminal-boarding**  Find out more about [standard notification webhooks](https://docs.adyen.com/development-resources/webhooks/understand-notifications#event-codes) and [other types of notifications](https://docs.adyen.com/development-resources/webhooks/understand-notifications#other-notifications).
   * @return type
   */
  @ApiModelProperty(required = true, value = "The type of webhook that is being created. Possible values are:  - **standard** - **account-settings-notification** - **banktransfer-notification** - **boletobancario-notification** - **directdebit-notification** - **ach-notification-of-change-notification** - **pending-notification** - **ideal-notification** - **ideal-pending-notification** - **report-notification** - **rreq-notification** - **terminal-settings** - **terminal-boarding**  Find out more about [standard notification webhooks](https://docs.adyen.com/development-resources/webhooks/understand-notifications#event-codes) and [other types of notifications](https://docs.adyen.com/development-resources/webhooks/understand-notifications#other-notifications).")
  @JsonProperty(JSON_PROPERTY_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getType() {
    return type;
  }

  /**
   * The type of webhook that is being created. Possible values are:  - **standard** - **account-settings-notification** - **banktransfer-notification** - **boletobancario-notification** - **directdebit-notification** - **ach-notification-of-change-notification** - **pending-notification** - **ideal-notification** - **ideal-pending-notification** - **report-notification** - **rreq-notification** - **terminal-settings** - **terminal-boarding**  Find out more about [standard notification webhooks](https://docs.adyen.com/development-resources/webhooks/understand-notifications#event-codes) and [other types of notifications](https://docs.adyen.com/development-resources/webhooks/understand-notifications#other-notifications).
   *
   * @param type
   */ 
  @JsonProperty(JSON_PROPERTY_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setType(String type) {
    this.type = type;
  }

  /**
   * Public URL where webhooks will be sent, for example **https://www.domain.com/webhook-endpoint**.
   *
   * @param url
   * @return the current {@code CreateMerchantWebhookRequest} instance, allowing for method chaining
   */
  public CreateMerchantWebhookRequest url(String url) {
    this.url = url;
    return this;
  }

  /**
   * Public URL where webhooks will be sent, for example **https://www.domain.com/webhook-endpoint**.
   * @return url
   */
  @ApiModelProperty(example = "http://www.adyen.com", required = true, value = "Public URL where webhooks will be sent, for example **https://www.domain.com/webhook-endpoint**.")
  @JsonProperty(JSON_PROPERTY_URL)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getUrl() {
    return url;
  }

  /**
   * Public URL where webhooks will be sent, for example **https://www.domain.com/webhook-endpoint**.
   *
   * @param url
   */ 
  @JsonProperty(JSON_PROPERTY_URL)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setUrl(String url) {
    this.url = url;
  }

  /**
   * Username to access the webhook URL.
   *
   * @param username
   * @return the current {@code CreateMerchantWebhookRequest} instance, allowing for method chaining
   */
  public CreateMerchantWebhookRequest username(String username) {
    this.username = username;
    return this;
  }

  /**
   * Username to access the webhook URL.
   * @return username
   */
  @ApiModelProperty(value = "Username to access the webhook URL.")
  @JsonProperty(JSON_PROPERTY_USERNAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getUsername() {
    return username;
  }

  /**
   * Username to access the webhook URL.
   *
   * @param username
   */ 
  @JsonProperty(JSON_PROPERTY_USERNAME)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setUsername(String username) {
    this.username = username;
  }

  /**
   * Return true if this CreateMerchantWebhookRequest object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    CreateMerchantWebhookRequest createMerchantWebhookRequest = (CreateMerchantWebhookRequest) o;
    return Objects.equals(this.acceptsExpiredCertificate, createMerchantWebhookRequest.acceptsExpiredCertificate) &&
        Objects.equals(this.acceptsSelfSignedCertificate, createMerchantWebhookRequest.acceptsSelfSignedCertificate) &&
        Objects.equals(this.acceptsUntrustedRootCertificate, createMerchantWebhookRequest.acceptsUntrustedRootCertificate) &&
        Objects.equals(this.active, createMerchantWebhookRequest.active) &&
        Objects.equals(this.additionalSettings, createMerchantWebhookRequest.additionalSettings) &&
        Objects.equals(this.communicationFormat, createMerchantWebhookRequest.communicationFormat) &&
        Objects.equals(this.description, createMerchantWebhookRequest.description) &&
        Objects.equals(this.encryptionProtocol, createMerchantWebhookRequest.encryptionProtocol) &&
        Objects.equals(this.networkType, createMerchantWebhookRequest.networkType) &&
        Objects.equals(this.password, createMerchantWebhookRequest.password) &&
        Objects.equals(this.populateSoapActionHeader, createMerchantWebhookRequest.populateSoapActionHeader) &&
        Objects.equals(this.type, createMerchantWebhookRequest.type) &&
        Objects.equals(this.url, createMerchantWebhookRequest.url) &&
        Objects.equals(this.username, createMerchantWebhookRequest.username);
  }

  @Override
  public int hashCode() {
    return Objects.hash(acceptsExpiredCertificate, acceptsSelfSignedCertificate, acceptsUntrustedRootCertificate, active, additionalSettings, communicationFormat, description, encryptionProtocol, networkType, password, populateSoapActionHeader, type, url, username);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class CreateMerchantWebhookRequest {\n");
    sb.append("    acceptsExpiredCertificate: ").append(toIndentedString(acceptsExpiredCertificate)).append("\n");
    sb.append("    acceptsSelfSignedCertificate: ").append(toIndentedString(acceptsSelfSignedCertificate)).append("\n");
    sb.append("    acceptsUntrustedRootCertificate: ").append(toIndentedString(acceptsUntrustedRootCertificate)).append("\n");
    sb.append("    active: ").append(toIndentedString(active)).append("\n");
    sb.append("    additionalSettings: ").append(toIndentedString(additionalSettings)).append("\n");
    sb.append("    communicationFormat: ").append(toIndentedString(communicationFormat)).append("\n");
    sb.append("    description: ").append(toIndentedString(description)).append("\n");
    sb.append("    encryptionProtocol: ").append(toIndentedString(encryptionProtocol)).append("\n");
    sb.append("    networkType: ").append(toIndentedString(networkType)).append("\n");
    sb.append("    password: ").append(toIndentedString(password)).append("\n");
    sb.append("    populateSoapActionHeader: ").append(toIndentedString(populateSoapActionHeader)).append("\n");
    sb.append("    type: ").append(toIndentedString(type)).append("\n");
    sb.append("    url: ").append(toIndentedString(url)).append("\n");
    sb.append("    username: ").append(toIndentedString(username)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

/**
   * Create an instance of CreateMerchantWebhookRequest given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of CreateMerchantWebhookRequest
   * @throws JsonProcessingException if the JSON string is invalid with respect to CreateMerchantWebhookRequest
   */
  public static CreateMerchantWebhookRequest fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, CreateMerchantWebhookRequest.class);
  }
/**
  * Convert an instance of CreateMerchantWebhookRequest to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
