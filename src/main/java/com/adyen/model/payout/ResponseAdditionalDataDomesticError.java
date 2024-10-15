/*
 * Adyen Payout API
 *
 * The version of the OpenAPI document: 68
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.payout;

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
 * ResponseAdditionalDataDomesticError
 */
@JsonPropertyOrder({
  ResponseAdditionalDataDomesticError.JSON_PROPERTY_DOMESTIC_REFUSAL_REASON_RAW,
  ResponseAdditionalDataDomesticError.JSON_PROPERTY_DOMESTIC_SHOPPER_ADVICE
})

public class ResponseAdditionalDataDomesticError {
  public static final String JSON_PROPERTY_DOMESTIC_REFUSAL_REASON_RAW = "domesticRefusalReasonRaw";
  private String domesticRefusalReasonRaw;

  public static final String JSON_PROPERTY_DOMESTIC_SHOPPER_ADVICE = "domesticShopperAdvice";
  private String domesticShopperAdvice;

  public ResponseAdditionalDataDomesticError() { 
  }

  /**
   * The reason the transaction was declined, given by the local issuer.  Currently available for merchants in Japan.
   *
   * @param domesticRefusalReasonRaw
   * @return the current {@code ResponseAdditionalDataDomesticError} instance, allowing for method chaining
   */
  public ResponseAdditionalDataDomesticError domesticRefusalReasonRaw(String domesticRefusalReasonRaw) {
    this.domesticRefusalReasonRaw = domesticRefusalReasonRaw;
    return this;
  }

  /**
   * The reason the transaction was declined, given by the local issuer.  Currently available for merchants in Japan.
   * @return domesticRefusalReasonRaw
   */
  @ApiModelProperty(value = "The reason the transaction was declined, given by the local issuer.  Currently available for merchants in Japan.")
  @JsonProperty(JSON_PROPERTY_DOMESTIC_REFUSAL_REASON_RAW)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getDomesticRefusalReasonRaw() {
    return domesticRefusalReasonRaw;
  }

  /**
   * The reason the transaction was declined, given by the local issuer.  Currently available for merchants in Japan.
   *
   * @param domesticRefusalReasonRaw
   */ 
  @JsonProperty(JSON_PROPERTY_DOMESTIC_REFUSAL_REASON_RAW)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setDomesticRefusalReasonRaw(String domesticRefusalReasonRaw) {
    this.domesticRefusalReasonRaw = domesticRefusalReasonRaw;
  }

  /**
   * The action the shopper should take, in a local language.  Currently available in Japanese, for merchants in Japan.
   *
   * @param domesticShopperAdvice
   * @return the current {@code ResponseAdditionalDataDomesticError} instance, allowing for method chaining
   */
  public ResponseAdditionalDataDomesticError domesticShopperAdvice(String domesticShopperAdvice) {
    this.domesticShopperAdvice = domesticShopperAdvice;
    return this;
  }

  /**
   * The action the shopper should take, in a local language.  Currently available in Japanese, for merchants in Japan.
   * @return domesticShopperAdvice
   */
  @ApiModelProperty(value = "The action the shopper should take, in a local language.  Currently available in Japanese, for merchants in Japan.")
  @JsonProperty(JSON_PROPERTY_DOMESTIC_SHOPPER_ADVICE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getDomesticShopperAdvice() {
    return domesticShopperAdvice;
  }

  /**
   * The action the shopper should take, in a local language.  Currently available in Japanese, for merchants in Japan.
   *
   * @param domesticShopperAdvice
   */ 
  @JsonProperty(JSON_PROPERTY_DOMESTIC_SHOPPER_ADVICE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setDomesticShopperAdvice(String domesticShopperAdvice) {
    this.domesticShopperAdvice = domesticShopperAdvice;
  }

  /**
   * Return true if this ResponseAdditionalDataDomesticError object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ResponseAdditionalDataDomesticError responseAdditionalDataDomesticError = (ResponseAdditionalDataDomesticError) o;
    return Objects.equals(this.domesticRefusalReasonRaw, responseAdditionalDataDomesticError.domesticRefusalReasonRaw) &&
        Objects.equals(this.domesticShopperAdvice, responseAdditionalDataDomesticError.domesticShopperAdvice);
  }

  @Override
  public int hashCode() {
    return Objects.hash(domesticRefusalReasonRaw, domesticShopperAdvice);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ResponseAdditionalDataDomesticError {\n");
    sb.append("    domesticRefusalReasonRaw: ").append(toIndentedString(domesticRefusalReasonRaw)).append("\n");
    sb.append("    domesticShopperAdvice: ").append(toIndentedString(domesticShopperAdvice)).append("\n");
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
   * Create an instance of ResponseAdditionalDataDomesticError given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of ResponseAdditionalDataDomesticError
   * @throws JsonProcessingException if the JSON string is invalid with respect to ResponseAdditionalDataDomesticError
   */
  public static ResponseAdditionalDataDomesticError fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, ResponseAdditionalDataDomesticError.class);
  }
/**
  * Convert an instance of ResponseAdditionalDataDomesticError to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
