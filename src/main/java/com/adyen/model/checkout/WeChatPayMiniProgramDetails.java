/*
 * Adyen Checkout API
 *
 * The version of the OpenAPI document: 71
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.checkout;

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
 * WeChatPayMiniProgramDetails
 */
@JsonPropertyOrder({
  WeChatPayMiniProgramDetails.JSON_PROPERTY_APP_ID,
  WeChatPayMiniProgramDetails.JSON_PROPERTY_CHECKOUT_ATTEMPT_ID,
  WeChatPayMiniProgramDetails.JSON_PROPERTY_OPENID,
  WeChatPayMiniProgramDetails.JSON_PROPERTY_TYPE
})

public class WeChatPayMiniProgramDetails {
  public static final String JSON_PROPERTY_APP_ID = "appId";
  private String appId;

  public static final String JSON_PROPERTY_CHECKOUT_ATTEMPT_ID = "checkoutAttemptId";
  private String checkoutAttemptId;

  public static final String JSON_PROPERTY_OPENID = "openid";
  private String openid;

  /**
   * **wechatpayMiniProgram**
   */
  public enum TypeEnum {
    WECHATPAYMINIPROGRAM("wechatpayMiniProgram");

    private String value;

    TypeEnum(String value) {
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
    public static TypeEnum fromValue(String value) {
      for (TypeEnum b : TypeEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_TYPE = "type";
  private TypeEnum type;

  public WeChatPayMiniProgramDetails() { 
  }

  public WeChatPayMiniProgramDetails appId(String appId) {
    this.appId = appId;
    return this;
  }

   /**
   * Get appId
   * @return appId
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_APP_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getAppId() {
    return appId;
  }


 /**
  * appId
  *
  * @param appId
  */ 
  @JsonProperty(JSON_PROPERTY_APP_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAppId(String appId) {
    this.appId = appId;
  }


  public WeChatPayMiniProgramDetails checkoutAttemptId(String checkoutAttemptId) {
    this.checkoutAttemptId = checkoutAttemptId;
    return this;
  }

   /**
   * The checkout attempt identifier.
   * @return checkoutAttemptId
  **/
  @ApiModelProperty(value = "The checkout attempt identifier.")
  @JsonProperty(JSON_PROPERTY_CHECKOUT_ATTEMPT_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getCheckoutAttemptId() {
    return checkoutAttemptId;
  }


 /**
  * The checkout attempt identifier.
  *
  * @param checkoutAttemptId
  */ 
  @JsonProperty(JSON_PROPERTY_CHECKOUT_ATTEMPT_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCheckoutAttemptId(String checkoutAttemptId) {
    this.checkoutAttemptId = checkoutAttemptId;
  }


  public WeChatPayMiniProgramDetails openid(String openid) {
    this.openid = openid;
    return this;
  }

   /**
   * Get openid
   * @return openid
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_OPENID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getOpenid() {
    return openid;
  }


 /**
  * openid
  *
  * @param openid
  */ 
  @JsonProperty(JSON_PROPERTY_OPENID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setOpenid(String openid) {
    this.openid = openid;
  }


  public WeChatPayMiniProgramDetails type(TypeEnum type) {
    this.type = type;
    return this;
  }

   /**
   * **wechatpayMiniProgram**
   * @return type
  **/
  @ApiModelProperty(value = "**wechatpayMiniProgram**")
  @JsonProperty(JSON_PROPERTY_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public TypeEnum getType() {
    return type;
  }


 /**
  * **wechatpayMiniProgram**
  *
  * @param type
  */ 
  @JsonProperty(JSON_PROPERTY_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setType(TypeEnum type) {
    this.type = type;
  }


  /**
   * Return true if this WeChatPayMiniProgramDetails object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    WeChatPayMiniProgramDetails weChatPayMiniProgramDetails = (WeChatPayMiniProgramDetails) o;
    return Objects.equals(this.appId, weChatPayMiniProgramDetails.appId) &&
        Objects.equals(this.checkoutAttemptId, weChatPayMiniProgramDetails.checkoutAttemptId) &&
        Objects.equals(this.openid, weChatPayMiniProgramDetails.openid) &&
        Objects.equals(this.type, weChatPayMiniProgramDetails.type);
  }

  @Override
  public int hashCode() {
    return Objects.hash(appId, checkoutAttemptId, openid, type);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class WeChatPayMiniProgramDetails {\n");
    sb.append("    appId: ").append(toIndentedString(appId)).append("\n");
    sb.append("    checkoutAttemptId: ").append(toIndentedString(checkoutAttemptId)).append("\n");
    sb.append("    openid: ").append(toIndentedString(openid)).append("\n");
    sb.append("    type: ").append(toIndentedString(type)).append("\n");
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
   * Create an instance of WeChatPayMiniProgramDetails given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of WeChatPayMiniProgramDetails
   * @throws JsonProcessingException if the JSON string is invalid with respect to WeChatPayMiniProgramDetails
   */
  public static WeChatPayMiniProgramDetails fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, WeChatPayMiniProgramDetails.class);
  }
/**
  * Convert an instance of WeChatPayMiniProgramDetails to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}

