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
import com.adyen.model.management.TransactionDescriptionInfo;
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
 * AccelInfo
 */
@JsonPropertyOrder({
  AccelInfo.JSON_PROPERTY_PROCESSING_TYPE,
  AccelInfo.JSON_PROPERTY_TRANSACTION_DESCRIPTION
})

public class AccelInfo {
  /**
   * The type of transactions processed over this payment method.  Allowed values: - **pos** for in-person payments.  - **billpay** for subscription payments, both the initial payment and the later recurring payments. These transactions have &#x60;recurringProcessingModel&#x60; **Subscription**.  - **ecom** for all other card not present transactions. This includes non-recurring transactions and transactions with &#x60;recurringProcessingModel&#x60; **CardOnFile** or **UnscheduledCardOnFile**. 
   */
  public enum ProcessingTypeEnum {
    BILLPAY("billpay"),
    
    ECOM("ecom"),
    
    POS("pos");

    private String value;

    ProcessingTypeEnum(String value) {
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
    public static ProcessingTypeEnum fromValue(String value) {
      for (ProcessingTypeEnum b : ProcessingTypeEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
  }

  public static final String JSON_PROPERTY_PROCESSING_TYPE = "processingType";
  private ProcessingTypeEnum processingType;

  public static final String JSON_PROPERTY_TRANSACTION_DESCRIPTION = "transactionDescription";
  private TransactionDescriptionInfo transactionDescription;

  public AccelInfo() { 
  }

  public AccelInfo processingType(ProcessingTypeEnum processingType) {
    this.processingType = processingType;
    return this;
  }

   /**
   * The type of transactions processed over this payment method.  Allowed values: - **pos** for in-person payments.  - **billpay** for subscription payments, both the initial payment and the later recurring payments. These transactions have &#x60;recurringProcessingModel&#x60; **Subscription**.  - **ecom** for all other card not present transactions. This includes non-recurring transactions and transactions with &#x60;recurringProcessingModel&#x60; **CardOnFile** or **UnscheduledCardOnFile**. 
   * @return processingType
  **/
  @ApiModelProperty(required = true, value = "The type of transactions processed over this payment method.  Allowed values: - **pos** for in-person payments.  - **billpay** for subscription payments, both the initial payment and the later recurring payments. These transactions have `recurringProcessingModel` **Subscription**.  - **ecom** for all other card not present transactions. This includes non-recurring transactions and transactions with `recurringProcessingModel` **CardOnFile** or **UnscheduledCardOnFile**. ")
  @JsonProperty(JSON_PROPERTY_PROCESSING_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public ProcessingTypeEnum getProcessingType() {
    return processingType;
  }


 /**
  * The type of transactions processed over this payment method.  Allowed values: - **pos** for in-person payments.  - **billpay** for subscription payments, both the initial payment and the later recurring payments. These transactions have &#x60;recurringProcessingModel&#x60; **Subscription**.  - **ecom** for all other card not present transactions. This includes non-recurring transactions and transactions with &#x60;recurringProcessingModel&#x60; **CardOnFile** or **UnscheduledCardOnFile**. 
  *
  * @param processingType
  */ 
  @JsonProperty(JSON_PROPERTY_PROCESSING_TYPE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setProcessingType(ProcessingTypeEnum processingType) {
    this.processingType = processingType;
  }


  public AccelInfo transactionDescription(TransactionDescriptionInfo transactionDescription) {
    this.transactionDescription = transactionDescription;
    return this;
  }

   /**
   * Get transactionDescription
   * @return transactionDescription
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_TRANSACTION_DESCRIPTION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public TransactionDescriptionInfo getTransactionDescription() {
    return transactionDescription;
  }


 /**
  * transactionDescription
  *
  * @param transactionDescription
  */ 
  @JsonProperty(JSON_PROPERTY_TRANSACTION_DESCRIPTION)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setTransactionDescription(TransactionDescriptionInfo transactionDescription) {
    this.transactionDescription = transactionDescription;
  }


  /**
   * Return true if this AccelInfo object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AccelInfo accelInfo = (AccelInfo) o;
    return Objects.equals(this.processingType, accelInfo.processingType) &&
        Objects.equals(this.transactionDescription, accelInfo.transactionDescription);
  }

  @Override
  public int hashCode() {
    return Objects.hash(processingType, transactionDescription);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AccelInfo {\n");
    sb.append("    processingType: ").append(toIndentedString(processingType)).append("\n");
    sb.append("    transactionDescription: ").append(toIndentedString(transactionDescription)).append("\n");
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
   * Create an instance of AccelInfo given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of AccelInfo
   * @throws JsonProcessingException if the JSON string is invalid with respect to AccelInfo
   */
  public static AccelInfo fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, AccelInfo.class);
  }
/**
  * Convert an instance of AccelInfo to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}

