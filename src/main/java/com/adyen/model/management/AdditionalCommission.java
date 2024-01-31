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
 * AdditionalCommission
 */
@JsonPropertyOrder({
  AdditionalCommission.JSON_PROPERTY_BALANCE_ACCOUNT_ID,
  AdditionalCommission.JSON_PROPERTY_FIXED_AMOUNT,
  AdditionalCommission.JSON_PROPERTY_VARIABLE_PERCENTAGE
})

public class AdditionalCommission {
  public static final String JSON_PROPERTY_BALANCE_ACCOUNT_ID = "balanceAccountId";
  private String balanceAccountId;

  public static final String JSON_PROPERTY_FIXED_AMOUNT = "fixedAmount";
  private Long fixedAmount;

  public static final String JSON_PROPERTY_VARIABLE_PERCENTAGE = "variablePercentage";
  private Long variablePercentage;

  public AdditionalCommission() { 
  }

  public AdditionalCommission balanceAccountId(String balanceAccountId) {
    this.balanceAccountId = balanceAccountId;
    return this;
  }

   /**
   * Unique identifier of the balance account to which the additional commission is booked.
   * @return balanceAccountId
  **/
  @ApiModelProperty(value = "Unique identifier of the balance account to which the additional commission is booked.")
  @JsonProperty(JSON_PROPERTY_BALANCE_ACCOUNT_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getBalanceAccountId() {
    return balanceAccountId;
  }


 /**
  * Unique identifier of the balance account to which the additional commission is booked.
  *
  * @param balanceAccountId
  */ 
  @JsonProperty(JSON_PROPERTY_BALANCE_ACCOUNT_ID)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setBalanceAccountId(String balanceAccountId) {
    this.balanceAccountId = balanceAccountId;
  }


  public AdditionalCommission fixedAmount(Long fixedAmount) {
    this.fixedAmount = fixedAmount;
    return this;
  }

   /**
   * A fixed commission fee, in minor units.
   * @return fixedAmount
  **/
  @ApiModelProperty(value = "A fixed commission fee, in minor units.")
  @JsonProperty(JSON_PROPERTY_FIXED_AMOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Long getFixedAmount() {
    return fixedAmount;
  }


 /**
  * A fixed commission fee, in minor units.
  *
  * @param fixedAmount
  */ 
  @JsonProperty(JSON_PROPERTY_FIXED_AMOUNT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setFixedAmount(Long fixedAmount) {
    this.fixedAmount = fixedAmount;
  }


  public AdditionalCommission variablePercentage(Long variablePercentage) {
    this.variablePercentage = variablePercentage;
    return this;
  }

   /**
   * A variable commission fee, in basis points.
   * @return variablePercentage
  **/
  @ApiModelProperty(value = "A variable commission fee, in basis points.")
  @JsonProperty(JSON_PROPERTY_VARIABLE_PERCENTAGE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Long getVariablePercentage() {
    return variablePercentage;
  }


 /**
  * A variable commission fee, in basis points.
  *
  * @param variablePercentage
  */ 
  @JsonProperty(JSON_PROPERTY_VARIABLE_PERCENTAGE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setVariablePercentage(Long variablePercentage) {
    this.variablePercentage = variablePercentage;
  }


  /**
   * Return true if this AdditionalCommission object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AdditionalCommission additionalCommission = (AdditionalCommission) o;
    return Objects.equals(this.balanceAccountId, additionalCommission.balanceAccountId) &&
        Objects.equals(this.fixedAmount, additionalCommission.fixedAmount) &&
        Objects.equals(this.variablePercentage, additionalCommission.variablePercentage);
  }

  @Override
  public int hashCode() {
    return Objects.hash(balanceAccountId, fixedAmount, variablePercentage);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AdditionalCommission {\n");
    sb.append("    balanceAccountId: ").append(toIndentedString(balanceAccountId)).append("\n");
    sb.append("    fixedAmount: ").append(toIndentedString(fixedAmount)).append("\n");
    sb.append("    variablePercentage: ").append(toIndentedString(variablePercentage)).append("\n");
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
   * Create an instance of AdditionalCommission given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of AdditionalCommission
   * @throws JsonProcessingException if the JSON string is invalid with respect to AdditionalCommission
   */
  public static AdditionalCommission fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, AdditionalCommission.class);
  }
/**
  * Convert an instance of AdditionalCommission to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}

