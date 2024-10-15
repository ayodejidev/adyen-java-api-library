/*
 * Transfers API
 *
 * The version of the OpenAPI document: 4
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.transfers;

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
 * BalanceMutation
 */
@JsonPropertyOrder({
  BalanceMutation.JSON_PROPERTY_BALANCE,
  BalanceMutation.JSON_PROPERTY_CURRENCY,
  BalanceMutation.JSON_PROPERTY_RECEIVED,
  BalanceMutation.JSON_PROPERTY_RESERVED
})

public class BalanceMutation {
  public static final String JSON_PROPERTY_BALANCE = "balance";
  private Long balance;

  public static final String JSON_PROPERTY_CURRENCY = "currency";
  private String currency;

  public static final String JSON_PROPERTY_RECEIVED = "received";
  private Long received;

  public static final String JSON_PROPERTY_RESERVED = "reserved";
  private Long reserved;

  public BalanceMutation() { 
  }

  /**
   * The amount in the payment&#39;s currency that is debited or credited on the balance accounting register.
   *
   * @param balance
   * @return the current {@code BalanceMutation} instance, allowing for method chaining
   */
  public BalanceMutation balance(Long balance) {
    this.balance = balance;
    return this;
  }

  /**
   * The amount in the payment&#39;s currency that is debited or credited on the balance accounting register.
   * @return balance
   */
  @ApiModelProperty(value = "The amount in the payment's currency that is debited or credited on the balance accounting register.")
  @JsonProperty(JSON_PROPERTY_BALANCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Long getBalance() {
    return balance;
  }

  /**
   * The amount in the payment&#39;s currency that is debited or credited on the balance accounting register.
   *
   * @param balance
   */ 
  @JsonProperty(JSON_PROPERTY_BALANCE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setBalance(Long balance) {
    this.balance = balance;
  }

  /**
   * The three-character [ISO currency code](https://docs.adyen.com/development-resources/currency-codes).
   *
   * @param currency
   * @return the current {@code BalanceMutation} instance, allowing for method chaining
   */
  public BalanceMutation currency(String currency) {
    this.currency = currency;
    return this;
  }

  /**
   * The three-character [ISO currency code](https://docs.adyen.com/development-resources/currency-codes).
   * @return currency
   */
  @ApiModelProperty(value = "The three-character [ISO currency code](https://docs.adyen.com/development-resources/currency-codes).")
  @JsonProperty(JSON_PROPERTY_CURRENCY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public String getCurrency() {
    return currency;
  }

  /**
   * The three-character [ISO currency code](https://docs.adyen.com/development-resources/currency-codes).
   *
   * @param currency
   */ 
  @JsonProperty(JSON_PROPERTY_CURRENCY)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCurrency(String currency) {
    this.currency = currency;
  }

  /**
   * The amount in the payment&#39;s currency that is debited or credited on the received accounting register.
   *
   * @param received
   * @return the current {@code BalanceMutation} instance, allowing for method chaining
   */
  public BalanceMutation received(Long received) {
    this.received = received;
    return this;
  }

  /**
   * The amount in the payment&#39;s currency that is debited or credited on the received accounting register.
   * @return received
   */
  @ApiModelProperty(value = "The amount in the payment's currency that is debited or credited on the received accounting register.")
  @JsonProperty(JSON_PROPERTY_RECEIVED)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Long getReceived() {
    return received;
  }

  /**
   * The amount in the payment&#39;s currency that is debited or credited on the received accounting register.
   *
   * @param received
   */ 
  @JsonProperty(JSON_PROPERTY_RECEIVED)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setReceived(Long received) {
    this.received = received;
  }

  /**
   * The amount in the payment&#39;s currency that is debited or credited on the reserved accounting register.
   *
   * @param reserved
   * @return the current {@code BalanceMutation} instance, allowing for method chaining
   */
  public BalanceMutation reserved(Long reserved) {
    this.reserved = reserved;
    return this;
  }

  /**
   * The amount in the payment&#39;s currency that is debited or credited on the reserved accounting register.
   * @return reserved
   */
  @ApiModelProperty(value = "The amount in the payment's currency that is debited or credited on the reserved accounting register.")
  @JsonProperty(JSON_PROPERTY_RESERVED)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public Long getReserved() {
    return reserved;
  }

  /**
   * The amount in the payment&#39;s currency that is debited or credited on the reserved accounting register.
   *
   * @param reserved
   */ 
  @JsonProperty(JSON_PROPERTY_RESERVED)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setReserved(Long reserved) {
    this.reserved = reserved;
  }

  /**
   * Return true if this BalanceMutation object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    BalanceMutation balanceMutation = (BalanceMutation) o;
    return Objects.equals(this.balance, balanceMutation.balance) &&
        Objects.equals(this.currency, balanceMutation.currency) &&
        Objects.equals(this.received, balanceMutation.received) &&
        Objects.equals(this.reserved, balanceMutation.reserved);
  }

  @Override
  public int hashCode() {
    return Objects.hash(balance, currency, received, reserved);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class BalanceMutation {\n");
    sb.append("    balance: ").append(toIndentedString(balance)).append("\n");
    sb.append("    currency: ").append(toIndentedString(currency)).append("\n");
    sb.append("    received: ").append(toIndentedString(received)).append("\n");
    sb.append("    reserved: ").append(toIndentedString(reserved)).append("\n");
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
   * Create an instance of BalanceMutation given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of BalanceMutation
   * @throws JsonProcessingException if the JSON string is invalid with respect to BalanceMutation
   */
  public static BalanceMutation fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, BalanceMutation.class);
  }
/**
  * Convert an instance of BalanceMutation to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
