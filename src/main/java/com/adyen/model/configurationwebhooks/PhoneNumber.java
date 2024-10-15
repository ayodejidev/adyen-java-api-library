/*
 * Configuration webhooks
 *
 * The version of the OpenAPI document: 2
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.configurationwebhooks;

import java.util.Objects;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
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
 * PhoneNumber
 */
@JsonPropertyOrder({
  PhoneNumber.JSON_PROPERTY_PHONE_COUNTRY_CODE,
  PhoneNumber.JSON_PROPERTY_PHONE_NUMBER,
  PhoneNumber.JSON_PROPERTY_PHONE_TYPE
})

public class PhoneNumber {
  public static final String JSON_PROPERTY_PHONE_COUNTRY_CODE = "phoneCountryCode";
  private String phoneCountryCode;

  public static final String JSON_PROPERTY_PHONE_NUMBER = "phoneNumber";
  private String phoneNumber;

  /**
   * The type of the phone number. Possible values: **Landline**, **Mobile**, **SIP**, **Fax**.
   */
  public enum PhoneTypeEnum {
    FAX("Fax"),
    
    LANDLINE("Landline"),
    
    MOBILE("Mobile"),
    
    SIP("SIP");

    private String value;

    PhoneTypeEnum(String value) {
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
    public static PhoneTypeEnum fromValue(String value) {
      for (PhoneTypeEnum b : PhoneTypeEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_PHONE_TYPE = "phoneType";
  private PhoneTypeEnum phoneType;

  public PhoneNumber() { 
  }

  /**
   * The two-character ISO-3166-1 alpha-2 country code of the phone number. For example, **US** or **NL**.
   *
   * @param phoneCountryCode
   * @return the current {@code PhoneNumber} instance, allowing for method chaining
   */
  public PhoneNumber phoneCountryCode(String phoneCountryCode) {
    this.phoneCountryCode = phoneCountryCode;
    return this;
  }

  /**
   * The two-character ISO-3166-1 alpha-2 country code of the phone number. For example, **US** or **NL**.
   * @return phoneCountryCode
   */
  @ApiModelProperty(value = "The two-character ISO-3166-1 alpha-2 country code of the phone number. For example, **US** or **NL**.")
  @JsonProperty(JSON_PROPERTY_PHONE_COUNTRY_CODE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getPhoneCountryCode() {
    return phoneCountryCode;
  }

  /**
   * The two-character ISO-3166-1 alpha-2 country code of the phone number. For example, **US** or **NL**.
   *
   * @param phoneCountryCode
   */ 
  @JsonProperty(JSON_PROPERTY_PHONE_COUNTRY_CODE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPhoneCountryCode(String phoneCountryCode) {
    this.phoneCountryCode = phoneCountryCode;
  }

  /**
   * The phone number. The inclusion of the phone number country code is not necessary.
   *
   * @param phoneNumber
   * @return the current {@code PhoneNumber} instance, allowing for method chaining
   */
  public PhoneNumber phoneNumber(String phoneNumber) {
    this.phoneNumber = phoneNumber;
    return this;
  }

  /**
   * The phone number. The inclusion of the phone number country code is not necessary.
   * @return phoneNumber
   */
  @ApiModelProperty(value = "The phone number. The inclusion of the phone number country code is not necessary.")
  @JsonProperty(JSON_PROPERTY_PHONE_NUMBER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getPhoneNumber() {
    return phoneNumber;
  }

  /**
   * The phone number. The inclusion of the phone number country code is not necessary.
   *
   * @param phoneNumber
   */ 
  @JsonProperty(JSON_PROPERTY_PHONE_NUMBER)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPhoneNumber(String phoneNumber) {
    this.phoneNumber = phoneNumber;
  }

  /**
   * The type of the phone number. Possible values: **Landline**, **Mobile**, **SIP**, **Fax**.
   *
   * @param phoneType
   * @return the current {@code PhoneNumber} instance, allowing for method chaining
   */
  public PhoneNumber phoneType(PhoneTypeEnum phoneType) {
    this.phoneType = phoneType;
    return this;
  }

  /**
   * The type of the phone number. Possible values: **Landline**, **Mobile**, **SIP**, **Fax**.
   * @return phoneType
   */
  @ApiModelProperty(value = "The type of the phone number. Possible values: **Landline**, **Mobile**, **SIP**, **Fax**.")
  @JsonProperty(JSON_PROPERTY_PHONE_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public PhoneTypeEnum getPhoneType() {
    return phoneType;
  }

  /**
   * The type of the phone number. Possible values: **Landline**, **Mobile**, **SIP**, **Fax**.
   *
   * @param phoneType
   */ 
  @JsonProperty(JSON_PROPERTY_PHONE_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setPhoneType(PhoneTypeEnum phoneType) {
    this.phoneType = phoneType;
  }

  /**
   * Return true if this PhoneNumber object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    PhoneNumber phoneNumber = (PhoneNumber) o;
    return Objects.equals(this.phoneCountryCode, phoneNumber.phoneCountryCode) &&
        Objects.equals(this.phoneNumber, phoneNumber.phoneNumber) &&
        Objects.equals(this.phoneType, phoneNumber.phoneType);
  }

  @Override
  public int hashCode() {
    return Objects.hash(phoneCountryCode, phoneNumber, phoneType);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class PhoneNumber {\n");
    sb.append("    phoneCountryCode: ").append(toIndentedString(phoneCountryCode)).append("\n");
    sb.append("    phoneNumber: ").append(toIndentedString(phoneNumber)).append("\n");
    sb.append("    phoneType: ").append(toIndentedString(phoneType)).append("\n");
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
   * Create an instance of PhoneNumber given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of PhoneNumber
   * @throws JsonProcessingException if the JSON string is invalid with respect to PhoneNumber
   */
  public static PhoneNumber fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, PhoneNumber.class);
  }
/**
  * Convert an instance of PhoneNumber to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
