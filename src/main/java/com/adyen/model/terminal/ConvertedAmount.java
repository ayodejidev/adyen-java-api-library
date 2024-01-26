/*
 * Adyen Terminal API
 *
 * The version of the OpenAPI document: 1
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.terminal;

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
import java.math.BigDecimal;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;


/**
 * ConvertedAmount
 */
@JsonPropertyOrder({
  ConvertedAmount.JSON_PROPERTY_AMOUNT_VALUE,
  ConvertedAmount.JSON_PROPERTY_CURRENCY
})

public class ConvertedAmount {
  public static final String JSON_PROPERTY_AMOUNT_VALUE = "AmountValue";
  private BigDecimal amountValue;

  public static final String JSON_PROPERTY_CURRENCY = "Currency";
  private String currency;

  public ConvertedAmount() { 
  }

  public ConvertedAmount amountValue(BigDecimal amountValue) {
    this.amountValue = amountValue;
    return this;
  }

   /**
   * Get amountValue
   * minimum: 0.0
   * maximum: 99999999.999999
   * @return amountValue
  **/
  @ApiModelProperty(required = true, value = "")
  @JsonProperty(JSON_PROPERTY_AMOUNT_VALUE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public BigDecimal getAmountValue() {
    return amountValue;
  }


 /**
  * amountValue
  *
  * @param amountValue
  */ 
  @JsonProperty(JSON_PROPERTY_AMOUNT_VALUE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAmountValue(BigDecimal amountValue) {
    this.amountValue = amountValue;
  }


  public ConvertedAmount currency(String currency) {
    this.currency = currency;
    return this;
  }

   /**
   * Get currency
   * @return currency
  **/
  @ApiModelProperty(required = true, value = "")
  @JsonProperty(JSON_PROPERTY_CURRENCY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getCurrency() {
    return currency;
  }


 /**
  * currency
  *
  * @param currency
  */ 
  @JsonProperty(JSON_PROPERTY_CURRENCY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCurrency(String currency) {
    this.currency = currency;
  }


  /**
   * Return true if this ConvertedAmount object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ConvertedAmount convertedAmount = (ConvertedAmount) o;
    return Objects.equals(this.amountValue, convertedAmount.amountValue) &&
        Objects.equals(this.currency, convertedAmount.currency);
  }

  @Override
  public int hashCode() {
    return Objects.hash(amountValue, currency);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ConvertedAmount {\n");
    sb.append("    amountValue: ").append(toIndentedString(amountValue)).append("\n");
    sb.append("    currency: ").append(toIndentedString(currency)).append("\n");
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
   * Create an instance of ConvertedAmount given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of ConvertedAmount
   * @throws JsonProcessingException if the JSON string is invalid with respect to ConvertedAmount
   */
  public static ConvertedAmount fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, ConvertedAmount.class);
  }
/**
  * Convert an instance of ConvertedAmount to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
