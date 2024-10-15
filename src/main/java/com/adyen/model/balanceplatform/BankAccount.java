/*
 * Configuration API
 *
 * The version of the OpenAPI document: 2
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.balanceplatform;

import java.util.Objects;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import com.adyen.model.balanceplatform.BankAccountAccountIdentification;
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
 * BankAccount
 */
@JsonPropertyOrder({
  BankAccount.JSON_PROPERTY_ACCOUNT_IDENTIFICATION
})

public class BankAccount {
  public static final String JSON_PROPERTY_ACCOUNT_IDENTIFICATION = "accountIdentification";
  private BankAccountAccountIdentification accountIdentification;

  public BankAccount() { 
  }

  /**
   * accountIdentification
   *
   * @param accountIdentification
   * @return the current {@code BankAccount} instance, allowing for method chaining
   */
  public BankAccount accountIdentification(BankAccountAccountIdentification accountIdentification) {
    this.accountIdentification = accountIdentification;
    return this;
  }

  /**
   * accountIdentification
   * @return accountIdentification
   */
  @ApiModelProperty(required = true, value = "")
  @JsonProperty(JSON_PROPERTY_ACCOUNT_IDENTIFICATION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public BankAccountAccountIdentification getAccountIdentification() {
    return accountIdentification;
  }

  /**
   * accountIdentification
   *
   * @param accountIdentification
   */ 
  @JsonProperty(JSON_PROPERTY_ACCOUNT_IDENTIFICATION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAccountIdentification(BankAccountAccountIdentification accountIdentification) {
    this.accountIdentification = accountIdentification;
  }

  /**
   * Return true if this BankAccount object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    BankAccount bankAccount = (BankAccount) o;
    return Objects.equals(this.accountIdentification, bankAccount.accountIdentification);
  }

  @Override
  public int hashCode() {
    return Objects.hash(accountIdentification);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class BankAccount {\n");
    sb.append("    accountIdentification: ").append(toIndentedString(accountIdentification)).append("\n");
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
   * Create an instance of BankAccount given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of BankAccount
   * @throws JsonProcessingException if the JSON string is invalid with respect to BankAccount
   */
  public static BankAccount fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, BankAccount.class);
  }
/**
  * Convert an instance of BankAccount to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
